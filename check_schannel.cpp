#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <string>
#include <unordered_map>
#include "MinHook.h"

#pragma comment(lib, "user32.lib")

using int_t = int;

using PFN_MH_Initialize   = int_t (WINAPI *)(void);
using PFN_MH_Uninitialize = int_t (WINAPI *)(void);
using PFN_MH_CreateHook   = int_t (WINAPI *)(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal);
using PFN_MH_EnableHook   = int_t (WINAPI *)(LPVOID pTarget);
using PFN_MH_DisableHook  = int_t (WINAPI *)(LPVOID pTarget);
using PFN_MH_RemoveHook   = int_t (WINAPI *)(LPVOID pTarget);

using UnsealMessage_t = NTSTATUS (WINAPI *)(
    void* ContextHandle,
    void* MessageBuffers,
    ULONG MessageSequenceNumber,
    PULONG QualityOfProtection
);

using SealMessage_t = NTSTATUS (WINAPI *)(
    void* ContextHandle,
    ULONG QualityOfProtection,
    void* MessageBuffers,
    ULONG MessageSequenceNumber
);

struct SecBuffer {
    ULONG cbBuffer;
    ULONG BufferType;
    void* pvBuffer;
};

struct SecBufferDesc {
    ULONG ulVersion;
    ULONG cBuffers;
    SecBuffer* pBuffers;
};

static UnsealMessage_t fpOriginalUnseal = nullptr;
static SealMessage_t   fpOriginalSeal   = nullptr;
static HANDLE hLogFile = NULL;
static HMODULE hMinHookDll = NULL;

static PFN_MH_Initialize   pMH_Initialize   = nullptr;
static PFN_MH_Uninitialize pMH_Uninitialize = nullptr;
static PFN_MH_CreateHook   pMH_CreateHook   = nullptr;
static PFN_MH_EnableHook   pMH_EnableHook   = nullptr;
static PFN_MH_DisableHook  pMH_DisableHook  = nullptr;
static PFN_MH_RemoveHook   pMH_RemoveHook   = nullptr;

static std::unordered_map<void*, std::string> g_partialHeaders;
static CRITICAL_SECTION g_cs;

static void EnsureLogOpen()
{
    if (hLogFile && hLogFile != INVALID_HANDLE_VALUE) return;

    char exePath[MAX_PATH] = {0};
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        std::string s(exePath);
        size_t pos = s.find_last_of("\\/");
        std::string dir = (pos == std::string::npos) ? "." : s.substr(0, pos);
        std::string fname = dir + "\\unseal_log.txt";
        hLogFile = CreateFileA(fname.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    }
}

static void Logf(const char* fmt, ...)
{
    EnsureLogOpen();
    char buffer[4096];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, fmt, ap);
    va_end(ap);

    DWORD written = 0;
    if (hLogFile && hLogFile != INVALID_HANDLE_VALUE) {
        WriteFile(hLogFile, buffer, (DWORD)strlen(buffer), &written, NULL);
        WriteFile(hLogFile, "\r\n", 2, &written, NULL);
    }
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
}

static void LogHRESULT(unsigned long long hr)
{
    DWORD code = (DWORD)(hr & 0xFFFFFFFF);
    LPSTR msg = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageA(flags, nullptr, code, 0, (LPSTR)&msg, 0, nullptr);
    if (len && msg) {
        while (len > 0 && (msg[len-1] == '\n' || msg[len-1] == '\r')) { msg[len-1] = '\0'; --len; }
        Logf("[HR] 0x%08llx -> %s", hr, msg);
        LocalFree(msg);
    } else {
        Logf("[HR] 0x%08llx (no system message)", hr);
    }
}

static const void* memmem_impl(const void* haystack, size_t haystacklen, const void* needle, size_t needlelen) {
    if (!haystack || !needle || haystacklen < needlelen) return nullptr;
    const unsigned char* h = (const unsigned char*)haystack;
    const unsigned char* n = (const unsigned char*)needle;
    for (size_t i = 0; i + needlelen <= haystacklen; ++i) {
        if (memcmp(h + i, n, needlelen) == 0) return h + i;
    }
    return nullptr;
}

static bool TryDetectAndLogHTTP(const char* prefix, const char* data, size_t len)
{
    if (!data || len < 4) return false;

    const char* crlf = (const char*)memmem_impl(data, len, "\r\n", 2);
    if (!crlf) return false;
    size_t firstLineLen = crlf - data;
    std::string firstLine(data, data + firstLineLen);

    if (firstLine.rfind("HTTP/", 0) == 0) {
        Logf("%s [HTTP-RESP] %s", prefix, firstLine.c_str());
        const char* headersEnd = (const char*)memmem_impl(data, len, "\r\n\r\n", 4);
        size_t headersLen = headersEnd ? (headersEnd - data) : firstLineLen;
        if (headersLen > firstLineLen) {
            std::string headers(data + firstLineLen + 2, data + headersLen);
            Logf("%s [HEADERS]\n%s", prefix, headers.c_str());
        }

        if (headersEnd) {
            size_t bodyOffset = (headersEnd - data) + 4;
            if (bodyOffset < len) {
                size_t bodyLen = len - bodyOffset;
                size_t toShow = bodyLen > 8192 ? 8192 : bodyLen;
                std::string body(data + bodyOffset, data + bodyOffset + toShow);
                for (char &c : body) if ((unsigned char)c < 0x20 && c != '\r' && c != '\n' && c != '\t') c = '.';
                Logf("%s [BODY - first %zu bytes]\n%s", prefix, toShow, body.c_str());
            }
        } else {
            size_t showLen = len - firstLineLen - 2;
            if (showLen > 0) {
                size_t toShow = showLen > 1024 ? 1024 : showLen;
                std::string rest(data + firstLineLen + 2, data + firstLineLen + 2 + toShow);
                for (char &c : rest) if ((unsigned char)c < 0x20 && c != '\r' && c != '\n' && c != '\t') c = '.';
                Logf("%s [RESP-TRAIL] %s", prefix, rest.c_str());
            }
        }
        return true;
    }

    size_t sp1 = firstLine.find(' ');
    size_t sp2 = firstLine.rfind(' ');
    if (sp1 != std::string::npos && sp2 != std::string::npos && sp2 > sp1) {
        std::string method = firstLine.substr(0, sp1);
        std::string url = firstLine.substr(sp1 + 1, sp2 - sp1 - 1);
        std::string protocol = firstLine.substr(sp2 + 1);
        if (protocol.rfind("HTTP/", 0) == 0) {
            Logf("%s [HTTP-REQ] Method=%s URL=%s", prefix, method.c_str(), url.c_str());
            const char* headersEnd = (const char*)memmem_impl(data, len, "\r\n\r\n", 4);
            if (headersEnd) {
                size_t headersLen = headersEnd - data;
                std::string headers(data + firstLineLen + 2, data + headersLen);
                Logf("%s [HEADERS]\n%s", prefix, headers.c_str());
                size_t bodyOffset = (headersEnd - data) + 4;
                if (bodyOffset < len) {
                    size_t bodyLen = len - bodyOffset;
                    size_t toShow = bodyLen > 8192 ? 8192 : bodyLen;
                    std::string body(data + bodyOffset, data + bodyOffset + toShow);
                    for (char &c : body) if ((unsigned char)c < 0x20 && c != '\r' && c != '\n' && c != '\t') c = '.';
                    Logf("%s [BODY - first %zu bytes]\n%s", prefix, toShow, body.c_str());
                }
            } else {
                size_t showLen = len - firstLineLen - 2;
                if (showLen > 0) {
                    size_t toShow = showLen > 1024 ? 1024 : showLen;
                    std::string rest(data + firstLineLen + 2, data + firstLineLen + 2 + toShow);
                    for (char &c : rest) if ((unsigned char)c < 0x20 && c != '\r' && c != '\n' && c != '\t') c = '.';
                    Logf("%s [REQ-TRAIL] %s", prefix, rest.c_str());
                }
            }
            return true;
        }
    }

    return false;
}

static void LogSecBufferDescData(const char* prefix, SecBufferDesc* desc)
{
    if (!desc) return;
    if (desc->cBuffers == 0 || !desc->pBuffers) return;

    for (ULONG i = 0; i < desc->cBuffers; ++i) {
        SecBuffer& buf = desc->pBuffers[i];
        if (buf.cbBuffer == 0 || !buf.pvBuffer) {
            Logf("%s Buffer[%u]: type=%u total=%u (empty)", prefix, i, buf.BufferType, buf.cbBuffer);
            continue;
        }

        if (buf.BufferType == 1) {
            size_t len = buf.cbBuffer > 65536 ? 65536 : buf.cbBuffer;
            const char* data = reinterpret_cast<const char*>(buf.pvBuffer);

            if (TryDetectAndLogHTTP(prefix, data, len)) {
                Logf("%s Buffer[%u]: total=%u shown=%zu (http-detected)", prefix, i, buf.cbBuffer, len);
                continue;
            }

            std::string s(data, data + len);
            for (char &c : s) {
                if ((unsigned char)c < 0x20 && c != '\r' && c != '\n' && c != '\t') c = '.';
            }

            Logf("%s Buffer[%u]: total=%u shown=%zu", prefix, i, buf.cbBuffer, len);
            const size_t CHUNK = 1000;
            for (size_t off = 0; off < s.size(); off += CHUNK) {
                size_t take = (s.size() - off > CHUNK) ? CHUNK : (s.size() - off);
                std::string part = s.substr(off, take);
                Logf("%s %s", prefix, part.c_str());
            }
        } else {
            Logf("%s Buffer[%u]: type=%u total=%u (skipped content)", prefix, i, buf.BufferType, buf.cbBuffer);
        }
    }
}

NTSTATUS WINAPI Hooked_UnsealMessage(
    void* ContextHandle,
    void* MessageBuffers,
    ULONG MessageSequenceNumber,
    PULONG QualityOfProtection
) {
    Logf("[HOOK] UnsealMessage called: Context=%p, MsgBuf=%p, Seq=%lu, QOP=%p",
         ContextHandle, MessageBuffers, MessageSequenceNumber, QualityOfProtection);

    NTSTATUS result = 0;
    if (fpOriginalUnseal) {
        result = fpOriginalUnseal(ContextHandle, MessageBuffers, MessageSequenceNumber, QualityOfProtection);
        Logf("[HOOK] Unseal: Original returned NTSTATUS=0x%08X", result);
        LogHRESULT(result);
    }

    if (result == 0x00000000 && MessageBuffers) {
        SecBufferDesc* desc = reinterpret_cast<SecBufferDesc*>(MessageBuffers);
        LogSecBufferDescData("[INCOMING]", desc);
    }
    return result;
}

NTSTATUS WINAPI Hooked_SealMessage(
    void* ContextHandle,
    ULONG QualityOfProtection,
    void* MessageBuffers,
    ULONG MessageSequenceNumber
) {
    Logf("[HOOK] SealMessage called: Context=%p, QOP=0x%X, MsgBuf=%p, Seq=%lu",
         ContextHandle, QualityOfProtection, MessageBuffers, MessageSequenceNumber);

    if (MessageBuffers && ContextHandle) {
        SecBufferDesc* desc = reinterpret_cast<SecBufferDesc*>(MessageBuffers);
        if (desc && desc->cBuffers && desc->pBuffers) {
            std::string assembled;
            for (ULONG i = 0; i < desc->cBuffers; ++i) {
                SecBuffer& buf = desc->pBuffers[i];
                if (buf.BufferType == 1 && buf.cbBuffer > 0 && buf.pvBuffer) {
                    size_t chunk = buf.cbBuffer > 16384 ? 16384 : buf.cbBuffer;
                    assembled.append((const char*)buf.pvBuffer, chunk);
                    if (assembled.size() > 128 * 1024) break;
                }
            }

            if (!assembled.empty()) {
                EnterCriticalSection(&g_cs);
                std::string &partial = g_partialHeaders[ContextHandle];
                partial.append(assembled);
                if (partial.size() > 256 * 1024) partial.erase(0, partial.size() - 256 * 1024);

                size_t hdrEnd = partial.find("\r\n\r\n");
                if (hdrEnd != std::string::npos) {
                    size_t firstLineEnd = partial.find("\r\n");
                    if (firstLineEnd != std::string::npos) {
                        std::string firstLine = partial.substr(0, firstLineEnd);
                        size_t sp1 = firstLine.find(' ');
                        size_t sp2 = firstLine.rfind(' ');
                        if (sp1 != std::string::npos && sp2 != std::string::npos && sp2 > sp1) {
                            std::string method = firstLine.substr(0, sp1);
                            std::string url = firstLine.substr(sp1 + 1, sp2 - sp1 - 1);
                            std::string protocol = firstLine.substr(sp2 + 1);
                            if (protocol.rfind("HTTP/", 0) == 0) {
                                Logf("[OUTGOING] Detected HTTP request: Method=%s URL=%s", method.c_str(), url.c_str());
                                std::string headers = partial.substr(firstLineEnd + 2, hdrEnd - (firstLineEnd + 2));
                                Logf("[OUTGOING] HEADERS:\n%s", headers.c_str());
                            } else {
                                Logf("[OUTGOING] First line (non-HTTP): %s", firstLine.c_str());
                            }
                        } else {
                            Logf("[OUTGOING] FirstLine: %s", firstLine.c_str());
                        }
                    }
                    partial.erase(0, hdrEnd + 4);
                }
                LeaveCriticalSection(&g_cs);

                TryDetectAndLogHTTP("[OUTGOING - QUICK]", assembled.data(), assembled.size());
            }
        }
    }

    NTSTATUS result = 0;
    if (fpOriginalSeal) {
        result = fpOriginalSeal(ContextHandle, QualityOfProtection, MessageBuffers, MessageSequenceNumber);
        Logf("[HOOK] Seal: Original returned NTSTATUS=0x%08X", result);
        LogHRESULT(result);
    }

    return result;
}

static HMODULE LoadMinHookNearModule(HMODULE hModule)
{
    if (!hModule) return nullptr;

    char modPath[MAX_PATH] = {0};
    if (!GetModuleFileNameA(hModule, modPath, MAX_PATH)) return nullptr;

    std::string s(modPath);
    size_t pos = s.find_last_of("\\/");
    std::string dir = (pos == std::string::npos) ? "." : s.substr(0, pos);
    std::string dllPath = dir + "\\MinHook.x64.dll";

    Logf("[INFO] Trying to load MinHook from: %s", dllPath.c_str());
    HMODULE h = LoadLibraryA(dllPath.c_str());
    if (h) {
        Logf("[OK] Loaded MinHook.dll from module dir: %s", dllPath.c_str());
        return h;
    }

    char sysPath[MAX_PATH];
    UINT n = GetSystemDirectoryA(sysPath, MAX_PATH);
    if (n && n < MAX_PATH) {
        std::string dllSys = std::string(sysPath) + "\\MinHook.x64.dll";
        Logf("[INFO] Trying to load MinHook from system dir: %s", dllSys.c_str());
        h = LoadLibraryA(dllSys.c_str());
        if (h) {
            Logf("[OK] Loaded MinHook.dll from system dir: %s", dllSys.c_str());
            return h;
        }
    }

    Logf("[ERR] Failed to load MinHook.x64.dll");
    return nullptr;
}

DWORD WINAPI WorkerThread(LPVOID)
{
    Logf("[INFO] WorkerThread started");

    const int wait_ms = 100;
    const int timeout_ms = 30000;
    int elapsed = 0;

    Logf("[START] Waiting for schannel.dll...");

    HMODULE hSchannel = NULL;
    FARPROC targetUnseal = NULL;
    FARPROC targetSeal = NULL;

    while (elapsed < timeout_ms) {
        hSchannel = GetModuleHandleA("schannel.dll");
        if (hSchannel) {
            Logf("[INFO] schannel.dll loaded at %p", hSchannel);
            targetUnseal = GetProcAddress(hSchannel, "UnsealMessage");
            targetSeal   = GetProcAddress(hSchannel, "SealMessage");
            if (targetUnseal) Logf("[OK] Found UnsealMessage -> %p", targetUnseal);
            if (targetSeal)   Logf("[OK] Found SealMessage   -> %p", targetSeal);
            break;
        }
        Sleep(wait_ms);
        elapsed += wait_ms;
    }

    if (!hSchannel) {
        Logf("[ERR] schannel.dll not found in %d ms", timeout_ms);
        return 1;
    }

    if (!targetUnseal && !targetSeal) {
        Logf("[ERR] Neither UnsealMessage nor SealMessage were found in schannel.dll");
        return 2;
    }

    hMinHookDll = LoadMinHookNearModule(hSchannel);
    if (!hMinHookDll) return 3;

    pMH_Initialize   = (PFN_MH_Initialize)GetProcAddress(hMinHookDll, "MH_Initialize");
    pMH_Uninitialize = (PFN_MH_Uninitialize)GetProcAddress(hMinHookDll, "MH_Uninitialize");
    pMH_CreateHook   = (PFN_MH_CreateHook)GetProcAddress(hMinHookDll, "MH_CreateHook");
    pMH_EnableHook   = (PFN_MH_EnableHook)GetProcAddress(hMinHookDll, "MH_EnableHook");
    pMH_DisableHook  = (PFN_MH_DisableHook)GetProcAddress(hMinHookDll, "MH_DisableHook");
    pMH_RemoveHook   = (PFN_MH_RemoveHook)GetProcAddress(hMinHookDll, "MH_RemoveHook");

    if (!pMH_Initialize || !pMH_CreateHook || !pMH_EnableHook || !pMH_DisableHook || !pMH_RemoveHook || !pMH_Uninitialize) {
        Logf("[ERR] One or more MinHook functions not found");
        FreeLibrary(hMinHookDll);
        hMinHookDll = NULL;
        return 4;
    }

    Logf("[INFO] MinHook functions found, initializing...");
    if (pMH_Initialize() != 0) {
        Logf("[ERR] MH_Initialize failed");
        FreeLibrary(hMinHookDll);
        hMinHookDll = NULL;
        return 5;
    }
    Logf("[OK] MinHook initialized");

    if (targetUnseal) {
        if (pMH_CreateHook((LPVOID)targetUnseal, (LPVOID)Hooked_UnsealMessage, reinterpret_cast<LPVOID*>(&fpOriginalUnseal)) != 0) {
            Logf("[ERR] MH_CreateHook Unseal failed");
        } else {
            if (pMH_EnableHook((LPVOID)targetUnseal) != 0) {
                Logf("[ERR] MH_EnableHook Unseal failed");
            } else {
                Logf("[OK] Hook enabled (Unseal): target=%p trampoline=%p", targetUnseal, fpOriginalUnseal);
            }
        }
    }

    if (targetSeal) {
        if (pMH_CreateHook((LPVOID)targetSeal, (LPVOID)Hooked_SealMessage, reinterpret_cast<LPVOID*>(&fpOriginalSeal)) != 0) {
            Logf("[ERR] MH_CreateHook Seal failed");
        } else {
            if (pMH_EnableHook((LPVOID)targetSeal) != 0) {
                Logf("[ERR] MH_EnableHook Seal failed");
            } else {
                Logf("[OK] Hook enabled (Seal): target=%p trampoline=%p", targetSeal, fpOriginalSeal);
            }
        }
    }

    while (true) {
        Sleep(1000);
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    OutputDebugStringA("[DLL] DllMain called\n");
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        Logf("[INFO] DLL_PROCESS_ATTACH");
        InitializeCriticalSection(&g_cs);
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        Logf("[INFO] DLL_PROCESS_DETACH: cleaning up");
        DeleteCriticalSection(&g_cs);
        if (pMH_DisableHook) pMH_DisableHook(NULL);
        if (pMH_RemoveHook) pMH_RemoveHook(NULL);
        if (pMH_Uninitialize) pMH_Uninitialize();
        if (hMinHookDll) {
            FreeLibrary(hMinHookDll);
            hMinHookDll = NULL;
        }
        if (hLogFile && hLogFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hLogFile);
            hLogFile = NULL;
        }
        break;
    }
    return TRUE;
}
