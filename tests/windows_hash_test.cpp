#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cassert>
#include <cstdio>
#include <string>
#include "../windows/monitor.hpp"

struct temporary_file {
    std::wstring path;
    temporary_file() {
        wchar_t root[MAX_PATH]{}, name[MAX_PATH]{};
        assert(GetTempPathW(MAX_PATH, root));
        assert(GetTempFileNameW(root, L"ohn", 0, name));
        path = name;
    }
    ~temporary_file() { DeleteFileW(path.c_str()); }
};

void write_image(const std::wstring& path, char content, FILETIME* preserved = nullptr) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, TRUNCATE_EXISTING, 0, nullptr);
    assert(file != INVALID_HANDLE_VALUE);
    const std::string bytes(4096, content);
    DWORD written = 0;
    assert(WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr));
    assert(written == bytes.size());
    if (preserved) assert(SetFileTime(file, nullptr, nullptr, preserved));
    CloseHandle(file);
}

int main() {
    temporary_file file, replacement;
    write_image(file.path, 'a');
    FILETIME mtime{};
    HANDLE handle = CreateFileW(file.path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    assert(handle != INVALID_HANDLE_VALUE);
    assert(GetFileTime(handle, nullptr, nullptr, &mtime));
    CloseHandle(handle);
    const auto first = program_image_hash(file.path);
    assert(first.size() == 64 && program_image_hash(file.path) == first);
    // An in-place update with a restored mtime must invalidate the cached hash.
    write_image(file.path, 'b', &mtime);
    const auto second = program_image_hash(file.path);
    assert(second.size() == 64 && second != first);
    // Replacing an image at the same path, size and mtime must also invalidate it.
    write_image(replacement.path, 'c', &mtime);
    assert(MoveFileExW(replacement.path.c_str(), file.path.c_str(), MOVEFILE_REPLACE_EXISTING));
    const auto third = program_image_hash(file.path);
    assert(third.size() == 64 && third != first && third != second);
    HANDLE stop = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    assert(stop && program_image_hash(file.path, stop).empty());
    CloseHandle(stop);
    // A writable handle prevents a stable read and must not reuse the cache.
    handle = CreateFileW(file.path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING, 0, nullptr);
    assert(handle != INVALID_HANDLE_VALUE);
    assert(program_image_hash(file.path).empty());
    CloseHandle(handle);
    std::puts("Program image identity, mutation and cancellation tests passed");
}
