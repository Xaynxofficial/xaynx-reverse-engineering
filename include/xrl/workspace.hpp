#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "xrl/json.hpp"

namespace xrl {

inline constexpr uint64_t kWorkspaceSchemaVersion = 2;
inline constexpr size_t kMaxWorkspaceBytes = 64 * 1024 * 1024;
inline constexpr size_t kMaxWorkspaceReportBytes = 8 * 1024 * 1024;

struct WorkspaceFile {
    std::string id;
    std::string path;
    std::string sha256;
    std::string format;
    std::string architecture;
    uint64_t size = 0;
    std::vector<std::string> tags;
};

struct WorkspaceBookmark {
    std::string id;
    std::string fileId;
    std::string fileHash;
    std::string title;
    std::string description;
    std::string kind;
    std::optional<uint64_t> address;
    std::optional<uint64_t> fileOffset;
    std::string createdAt;
    std::vector<std::string> tags;
};

struct WorkspaceNote {
    std::string id;
    std::string scope;
    std::string fileId;
    std::string fileHash;
    std::string title;
    std::string markdown;
    std::string createdAt;
    std::string modifiedAt;
    std::optional<uint64_t> address;
    std::vector<std::string> tags;
};

struct WorkspaceAnalysis {
    std::string id;
    std::string type;
    std::string fileId;
    std::string fileHash;
    std::string timestamp;
    std::string engineVersion;
    std::string status;
    std::string summary;
    std::string reportJson;
};

struct WorkspaceComparison {
    std::string id;
    std::string fileAId;
    std::string fileAHash;
    std::string fileBId;
    std::string fileBHash;
    std::string timestamp;
    std::string summary;
    std::string reportJson;
};

struct WorkspaceTag {
    std::string name;
    std::string color;
};

struct WorkspaceSession {
    std::string selectedFileId;
    int activePage = 0;
    std::optional<uint64_t> selectedAddress;
    std::optional<uint64_t> selectedFunction;
};

struct WorkspaceProject {
    std::string id;
    std::string name;
    std::string description;
    std::string category;
    std::string createdAt;
    std::string modifiedAt;
    uint64_t version = 1;
    std::vector<WorkspaceFile> files;
    std::vector<WorkspaceAnalysis> analyses;
    std::vector<WorkspaceComparison> comparisons;
    std::vector<WorkspaceBookmark> bookmarks;
    std::vector<WorkspaceNote> notes;
    std::vector<WorkspaceTag> tags;
    WorkspaceSession session;
};

struct WorkspaceData {
    uint64_t schemaVersion = kWorkspaceSchemaVersion;
    std::string lastActiveProjectId;
    std::vector<WorkspaceProject> projects;
};

struct WorkspaceLoadResult {
    bool ok = false;
    WorkspaceData data;
    std::string error;
    std::vector<std::string> warnings;
};

std::string makeWorkspaceId();
std::string renderWorkspaceJson(const WorkspaceData& data);
WorkspaceLoadResult parseWorkspaceJson(const std::string& json);
WorkspaceLoadResult readWorkspace(const std::filesystem::path& path);
bool writeWorkspace(const std::filesystem::path& path, const WorkspaceData& data,
                    std::string* error = nullptr);

WorkspaceProject* findWorkspaceProject(WorkspaceData& data, const std::string& projectId);
const WorkspaceProject* findWorkspaceProject(const WorkspaceData& data, const std::string& projectId);
WorkspaceFile* findWorkspaceFile(WorkspaceProject& project, const std::string& fileId);
const WorkspaceFile* findWorkspaceFile(const WorkspaceProject& project, const std::string& fileId);
std::string createWorkspaceProject(WorkspaceData& data, std::string name,
                                   std::string description = {}, std::string category = {});
bool renameWorkspaceProject(WorkspaceData& data, const std::string& projectId, std::string name);
std::optional<std::string> duplicateWorkspaceProject(WorkspaceData& data,
                                                      const std::string& projectId,
                                                      std::string name);
bool deleteWorkspaceProject(WorkspaceData& data, const std::string& projectId);
std::optional<std::string> addWorkspaceFile(WorkspaceProject& project, WorkspaceFile file);
bool removeWorkspaceFile(WorkspaceProject& project, const std::string& fileId);
bool renameWorkspaceTag(WorkspaceProject& project, const std::string& oldName,
                        const std::string& newName);
bool deleteWorkspaceTag(WorkspaceProject& project, const std::string& name);

}  // namespace xrl
