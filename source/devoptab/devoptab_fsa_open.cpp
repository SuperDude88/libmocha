#include "devoptab_fs.h"
#include "logger.h"
#include <mutex>

// Extended "magic" value that allows opening files with FS_OPEN_FLAG_UNENCRYPTED in underlying FSOpenFileEx() call similar to O_DIRECTORY
#ifndef O_UNENCRYPTED
#define O_UNENCRYPTED 0x4000000
#endif

int __fsa_open(struct _reent *r,
               void *fileStruct,
               const char *path,
               int flags,
               int mode) {
    FSAFileHandle fd;
    FSError status;
    const char *fsMode;
    __fsa_file_t *file;

    if (!fileStruct || !path) {
        r->_errno = EINVAL;
        return -1;
    }

    bool createFileManually = false;

    // Map flags to open modes
    int commonFlagMask = O_CREAT | O_TRUNC | O_APPEND;
    if (((flags & O_ACCMODE) == O_RDONLY) && !(flags & commonFlagMask)) {
        fsMode = "r";
    } else if (((flags & O_ACCMODE) == O_RDWR) && !(flags & commonFlagMask)) {
        fsMode = "r+";
    } else if (((flags & O_ACCMODE) == O_WRONLY) && ((flags & commonFlagMask) == (O_CREAT | O_TRUNC))) {
        fsMode = "w";
    } else if (((flags & O_ACCMODE) == O_RDWR) && ((flags & commonFlagMask) == (O_CREAT | O_TRUNC))) {
        fsMode = "w+";
    } else if (((flags & O_ACCMODE) == O_WRONLY) && ((flags & commonFlagMask) == (O_CREAT | O_APPEND))) {
        fsMode = "a";
    } else if (((flags & O_ACCMODE) == O_RDWR) && ((flags & commonFlagMask) == (O_CREAT | O_APPEND))) {
        fsMode = "a+";
    } else if (((flags & O_ACCMODE) == O_WRONLY) && ((flags & commonFlagMask) == (O_CREAT))) {
        // Cafe OS doesn't have a matching mode for this, so we have to be creative and create file manually.
        createFileManually = true;
        // It's not possible to open a file with write only mode which doesn't truncate the file
        // Technically we could read from the file, but our read implementation is blocking this.
        fsMode = "r+";
    } else {
        r->_errno = EINVAL;
        return -1;
    }

    char *fixedPath = __fsa_fixpath(r, path);
    if (!fixedPath) {
        r->_errno = ENOMEM;
        return -1;
    }

    // Open the file
    FSOpenFileFlags openFlags = (flags & O_UNENCRYPTED) ? FS_OPEN_FLAG_UNENCRYPTED : FS_OPEN_FLAG_NONE;

    auto *deviceData = (FSADeviceData *) r->deviceData;

    std::lock_guard<FastLockWrapper> lock(deviceData->mutex);

    FSMode translatedMode = __fsa_translate_permission_mode(mode);

    uint32_t preAllocSize = 0;

    // Check if we need to create the file manually
    if (createFileManually) {
        FSStat stat;
        status = FSAGetStat(deviceData->clientHandle, fixedPath, &stat);
        if (status == FS_ERROR_NOT_FOUND) {
            status = FSAOpenFileEx(deviceData->clientHandle, fixedPath, "w", translatedMode, openFlags, preAllocSize, &fd);
            if (status == FS_ERROR_OK) {
                FSACloseFile(deviceData->clientHandle, fd);
                fd = -1;
            }
        }
        if (status < 0) {
            free(fixedPath);
            r->_errno = __fsa_translate_error(status);
            return -1;
        }
    }

    status = FSAOpenFileEx(deviceData->clientHandle, fixedPath, fsMode, translatedMode, openFlags, preAllocSize, &fd);
    if (status < 0) {
        DEBUG_FUNCTION_LINE_ERR("FSAOpenFileEx(0x%08X, %s, %s, 0x%X, 0x%08X, 0x%08X, 0x%08X) failed: %s", deviceData->clientHandle, fixedPath, fsMode, translatedMode, openFlags, preAllocSize, &fd, FSAGetStatusStr(status));
        r->_errno = __fsa_translate_error(status);
        free(fixedPath);
        return -1;
    }

    // If O_CREAT and O_EXCL are set, open() shall fail if the file exists.
    if (flags & (O_EXCL | O_CREAT)) {
        FSACloseFile(deviceData->clientHandle, fd);
        r->_errno = EEXIST;
        return -1;
    }

    file        = (__fsa_file_t *) fileStruct;
    file->fd    = fd;
    file->flags = (flags & (O_ACCMODE | O_APPEND | O_SYNC));
    strncpy(file->path, fixedPath, FS_MAX_PATH);
    free(fixedPath);

    if (flags & O_APPEND) {
        status = FSAGetPosFile(deviceData->clientHandle, fd, &file->offset);
        if (status < 0) {
            DEBUG_FUNCTION_LINE_ERR("FSAGetPosFile(0x%08X, 0x%08X, 0x%08X) failed: %s", deviceData->clientHandle, fd, &file->offset, FSAGetStatusStr(status));
            r->_errno = __fsa_translate_error(status);
            if (FSACloseFile(deviceData->clientHandle, fd) < 0) {
                DEBUG_FUNCTION_LINE_ERR("FSACloseFile(0x%08X, 0x%08X) failed: %s", deviceData->clientHandle, fd, FSAGetStatusStr(status));
            }
            return -1;
        }
    } else {
        file->offset = 0;
    }
    return 0;
}