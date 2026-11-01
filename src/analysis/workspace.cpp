#include "xrl/workspace.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <ctime>
#include <fstream>
#include <limits>
#include <random>
#include <set>
#include <span>
#include <system_error>

#include "xrl/sha256.hpp"

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace xrl {
namespace {

constexpr size_t kMaxProjects = 10'000;
constexpr size_t kMaxFilesPerProject = 10'000;
constexpr size_t kMaxEntriesPerProject = 100'000;
constexpr size_t kMaxTagsPerProject = 1'000;

std::string value(const Json& object, const char* key) {
    const Json* field = object.find(key);
    return field && field->isString() ? field->asString() : std::string{};
}

uint64_t unsignedValue(const Json& object, const char* key, uint64_t fallback = 0) {
    const Json* field = object.find(key);
    if (!field) return fallback;
    if (field->isString()) {
        const auto& text = field->asString();
        uint64_t parsed = 0;
        const int base = text.starts_with("0x") || text.starts_with("0X") ? 16 : 10;
        const char* begin = text.data() + (base == 16 ? 2 : 0);
        const auto result = std::from_chars(begin, text.data() + text.size(), parsed, base);
        return result.ec == std::errc{} && result.ptr == text.data() + text.size() ? parsed : fallback;
    }
    if (field->type() == Json::Type::Int && field->asInt() >= 0)
        return static_cast<uint64_t>(field->asInt());
    return fallback;
}

std::optional<uint64_t> parseAddressText(const std::string& text) {
    uint64_t parsed = 0;
    const int base = text.starts_with("0x") || text.starts_with("0X") ? 16 : 10;
    const char* begin = text.data() + (base == 16 ? 2 : 0);
    if (begin == text.data() + text.size()) return std::nullopt;
    const auto result = std::from_chars(begin, text.data() + text.size(), parsed, base);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) return std::nullopt;
    return parsed;
}

Json addressValue(const std::optional<uint64_t>& address) {
    if (!address) return {};
    char buffer[19] = "0x";
    constexpr char digits[] = "0123456789abcdef";
    size_t count = 0;
    uint64_t n = *address;
    do {
        buffer[2 + count++] = digits[n & 0xFu];
        n >>= 4;
    } while (n && count < 16);
    std::reverse(buffer + 2, buffer + 2 + count);
    buffer[2 + count] = '\0';
    return std::string(buffer);
}

std::optional<uint64_t> optionalAddress(const Json& object, const char* key) {
    const Json* field = object.find(key);
    if (!field || field->isNull()) return std::nullopt;
    if (field->isString()) return parseAddressText(field->asString());
    if (field->type() == Json::Type::Int && field->asInt() >= 0)
        return static_cast<uint64_t>(field->asInt());
    return std::nullopt;
}

Json stringArray(const std::vector<std::string>& values) {
    Json array = Json::array();
    for (const auto& item : values) array.push(item);
    return array;
}

std::vector<std::string> readStringArray(const Json& object, const char* key, size_t limit,
                                         bool* valid) {
    std::vector<std::string> values;
    const Json* array = object.find(key);
    if (!array) return values;
    if (!array->isArray() || array->size() > limit) {
        *valid = false;
        return values;
    }
    values.reserve(array->size());
    for (const auto& item : array->items()) {
        if (!item.isString() || item.asString().size() > 4096) {
            *valid = false;
            return {};
        }
        values.push_back(item.asString());
    }
    return values;
}

Json fileToJson(const WorkspaceFile& file) {
    Json item = Json::object();
    item.set("id", file.id);
    item.set("path", file.path);
    item.set("sha256", file.sha256);
    item.set("format", file.format);
    item.set("architecture", file.architecture);
    item.set("size", std::to_string(file.size));
    item.set("tags", stringArray(file.tags));
    return item;
}

Json bookmarkToJson(const WorkspaceBookmark& bookmark) {
    Json item = Json::object();
    item.set("id", bookmark.id);
    item.set("file_id", bookmark.fileId);
    item.set("file_hash", bookmark.fileHash);
    item.set("title", bookmark.title);
    item.set("description", bookmark.description);
    item.set("kind", bookmark.kind);
    item.set("address", addressValue(bookmark.address));
    item.set("file_offset", addressValue(bookmark.fileOffset));
    item.set("created_at", bookmark.createdAt);
    item.set("tags", stringArray(bookmark.tags));
    return item;
}

Json noteToJson(const WorkspaceNote& note) {
    Json item = Json::object();
    item.set("id", note.id);
    item.set("scope", note.scope);
    item.set("file_id", note.fileId);
    item.set("file_hash", note.fileHash);
    item.set("title", note.title);
    item.set("markdown", note.markdown);
    item.set("created_at", note.createdAt);
    item.set("modified_at", note.modifiedAt);
    item.set("address", addressValue(note.address));
    item.set("tags", stringArray(note.tags));
    return item;
}

Json analysisToJson(const WorkspaceAnalysis& analysis) {
    Json item = Json::object();
    item.set("id", analysis.id);
    item.set("type", analysis.type);
    item.set("file_id", analysis.fileId);
    item.set("file_hash", analysis.fileHash);
    item.set("timestamp", analysis.timestamp);
    item.set("engine_version", analysis.engineVersion);
    item.set("status", analysis.status);
    item.set("summary", analysis.summary);
    item.set("report_json", analysis.reportJson);
    return item;
}

Json comparisonToJson(const WorkspaceComparison& comparison) {
    Json item = Json::object();
    item.set("id", comparison.id);
    item.set("file_a_id", comparison.fileAId);
    item.set("file_a_hash", comparison.fileAHash);
    item.set("file_b_id", comparison.fileBId);
    item.set("file_b_hash", comparison.fileBHash);
    item.set("timestamp", comparison.timestamp);
    item.set("summary", comparison.summary);
    item.set("report_json", comparison.reportJson);
    return item;
}

Json projectToJson(const WorkspaceProject& project) {
    Json item = Json::object();
    item.set("id", project.id);
    item.set("name", project.name);
    item.set("description", project.description);
    item.set("category", project.category);
    item.set("created_at", project.createdAt);
    item.set("modified_at", project.modifiedAt);
    item.set("version", std::to_string(project.version));

    Json files = Json::array();
    for (const auto& file : project.files) files.push(fileToJson(file));
    item.set("files", std::move(files));
    Json analyses = Json::array();
    for (const auto& analysis : project.analyses) analyses.push(analysisToJson(analysis));
    item.set("analyses", std::move(analyses));
    Json comparisons = Json::array();
    for (const auto& comparison : project.comparisons) comparisons.push(comparisonToJson(comparison));
    item.set("comparisons", std::move(comparisons));
    Json bookmarks = Json::array();
    for (const auto& bookmark : project.bookmarks) bookmarks.push(bookmarkToJson(bookmark));
    item.set("bookmarks", std::move(bookmarks));
    Json notes = Json::array();
    for (const auto& note : project.notes) notes.push(noteToJson(note));
    item.set("notes", std::move(notes));
    Json tags = Json::array();
    for (const auto& tag : project.tags) {
        Json value = Json::object();
        value.set("name", tag.name);
        value.set("color", tag.color);
        tags.push(std::move(value));
    }
    item.set("tags", std::move(tags));

    Json session = Json::object();
    session.set("selected_file_id", project.session.selectedFileId);
    session.set("active_page", project.session.activePage);
    session.set("selected_address", addressValue(project.session.selectedAddress));
    session.set("selected_function", addressValue(project.session.selectedFunction));
    item.set("session", std::move(session));
    return item;
}

bool readObjectArray(const Json& projectJson, const char* key, size_t limit,
                     std::vector<Json>* values, bool* valid) {
    const Json* array = projectJson.find(key);
    if (!array) return true;
    if (!array->isArray() || array->size() > limit) {
        *valid = false;
        return false;
    }
    values->assign(array->items().begin(), array->items().end());
    if (std::any_of(values->begin(), values->end(), [](const Json& item) { return !item.isObject(); })) {
        *valid = false;
        return false;
    }
    return true;
}

bool readProject(const Json& source, WorkspaceProject* project) {
    bool valid = true;
    project->id = value(source, "id");
    project->name = value(source, "name");
    project->description = value(source, "description");
    project->category = value(source, "category");
    project->createdAt = value(source, "created_at");
    project->modifiedAt = value(source, "modified_at");
    project->version = unsignedValue(source, "version", 1);
    if (project->id.empty() || project->id.size() > 128 ||
        project->name.empty() || project->name.size() > 512 ||
        project->description.size() > 1024 * 1024 ||
        project->category.size() > 512 || project->version == 0) return false;

    std::vector<Json> records;
    if (!readObjectArray(source, "files", kMaxFilesPerProject, &records, &valid)) return false;
    project->files.reserve(records.size());
    std::set<std::string> ids;
    for (const auto& record : records) {
        WorkspaceFile file;
        file.id = value(record, "id");
        file.path = value(record, "path");
        file.sha256 = value(record, "sha256");
        file.format = value(record, "format");
        file.architecture = value(record, "architecture");
        file.size = unsignedValue(record, "size");
        file.tags = readStringArray(record, "tags", kMaxTagsPerProject, &valid);
        if (file.id.empty() || !ids.insert(file.id).second || file.path.size() > 32'768 ||
            file.sha256.size() > 128 || file.format.size() > 128 ||
            file.architecture.size() > 128 || !valid) return false;
        project->files.push_back(std::move(file));
    }

    auto readRecords = [&](const char* key) {
        records.clear();
        return readObjectArray(source, key, kMaxEntriesPerProject, &records, &valid);
    };
    if (!readRecords("analyses")) return false;
    project->analyses.reserve(records.size());
    ids.clear();
    for (const auto& record : records) {
        WorkspaceAnalysis analysis;
        analysis.id = value(record, "id");
        analysis.type = value(record, "type");
        analysis.fileId = value(record, "file_id");
        analysis.fileHash = value(record, "file_hash");
        analysis.timestamp = value(record, "timestamp");
        analysis.engineVersion = value(record, "engine_version");
        analysis.status = value(record, "status");
        analysis.summary = value(record, "summary");
        analysis.reportJson = value(record, "report_json");
        if (analysis.id.empty() || !ids.insert(analysis.id).second ||
            analysis.type.size() > 128 || analysis.summary.size() > 1024 * 1024 ||
            analysis.reportJson.size() > kMaxWorkspaceReportBytes || !valid) return false;
        if (!analysis.reportJson.empty() && !Json::parse(analysis.reportJson).value) return false;
        project->analyses.push_back(std::move(analysis));
    }

    if (!readRecords("comparisons")) return false;
    project->comparisons.reserve(records.size());
    ids.clear();
    for (const auto& record : records) {
        WorkspaceComparison comparison;
        comparison.id = value(record, "id");
        comparison.fileAId = value(record, "file_a_id");
        comparison.fileAHash = value(record, "file_a_hash");
        comparison.fileBId = value(record, "file_b_id");
        comparison.fileBHash = value(record, "file_b_hash");
        comparison.timestamp = value(record, "timestamp");
        comparison.summary = value(record, "summary");
        comparison.reportJson = value(record, "report_json");
        if (comparison.id.empty() || !ids.insert(comparison.id).second ||
            comparison.summary.size() > 1024 * 1024 ||
            comparison.reportJson.size() > kMaxWorkspaceReportBytes || !valid) return false;
        if (!comparison.reportJson.empty() && !Json::parse(comparison.reportJson).value) return false;
        project->comparisons.push_back(std::move(comparison));
    }

    if (!readRecords("bookmarks")) return false;
    project->bookmarks.reserve(records.size());
    ids.clear();
    for (const auto& record : records) {
        WorkspaceBookmark bookmark;
        bookmark.id = value(record, "id");
        bookmark.fileId = value(record, "file_id");
        bookmark.fileHash = value(record, "file_hash");
        bookmark.title = value(record, "title");
        bookmark.description = value(record, "description");
        bookmark.kind = value(record, "kind");
        bookmark.address = optionalAddress(record, "address");
        bookmark.fileOffset = optionalAddress(record, "file_offset");
        bookmark.createdAt = value(record, "created_at");
        bookmark.tags = readStringArray(record, "tags", kMaxTagsPerProject, &valid);
        if (bookmark.id.empty() || !ids.insert(bookmark.id).second ||
            bookmark.title.size() > 512 || bookmark.description.size() > 1024 * 1024 ||
            bookmark.kind.size() > 128 || !valid) return false;
        project->bookmarks.push_back(std::move(bookmark));
    }

    if (!readRecords("notes")) return false;
    project->notes.reserve(records.size());
    ids.clear();
    for (const auto& record : records) {
        WorkspaceNote note;
        note.id = value(record, "id");
        note.scope = value(record, "scope");
        note.fileId = value(record, "file_id");
        note.fileHash = value(record, "file_hash");
        note.title = value(record, "title");
        note.markdown = value(record, "markdown");
        note.createdAt = value(record, "created_at");
        note.modifiedAt = value(record, "modified_at");
        note.address = optionalAddress(record, "address");
        note.tags = readStringArray(record, "tags", kMaxTagsPerProject, &valid);
        if (note.id.empty() || !ids.insert(note.id).second ||
            note.scope.size() > 128 || note.title.size() > 512 ||
            note.markdown.size() > 1024 * 1024 || !valid) return false;
        project->notes.push_back(std::move(note));
    }

    if (!readRecords("tags")) return false;
    project->tags.reserve(records.size());
    ids.clear();
    for (const auto& record : records) {
        WorkspaceTag tag{value(record, "name"), value(record, "color")};
        if (tag.name.empty() || tag.name.size() > 256 || !ids.insert(tag.name).second ||
            tag.color.size() > 64) return false;
        project->tags.push_back(std::move(tag));
    }

    if (const Json* session = source.find("session"); session && session->isObject()) {
        project->session.selectedFileId = value(*session, "selected_file_id");
        const Json* page = session->find("active_page");
        if (page && page->type() == Json::Type::Int)
            project->session.activePage = static_cast<int>(std::clamp<int64_t>(page->asInt(), 0, 1000));
        project->session.selectedAddress = optionalAddress(*session, "selected_address");
        project->session.selectedFunction = optionalAddress(*session, "selected_function");
    }
    if (!project->session.selectedFileId.empty() &&
        std::none_of(project->files.begin(), project->files.end(), [&](const WorkspaceFile& file) {
            return file.id == project->session.selectedFileId;
        })) project->session.selectedFileId.clear();
    return true;
}

void touch(WorkspaceProject& project) {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &time);
#else
    gmtime_r(&time, &utc);
#endif
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc);
    project.modifiedAt = buffer;
}

void removeFileOwnedEntries(WorkspaceProject& project, const std::string& fileId) {
    std::erase_if(project.analyses, [&](const WorkspaceAnalysis& entry) { return entry.fileId == fileId; });
    std::erase_if(project.bookmarks, [&](const WorkspaceBookmark& entry) { return entry.fileId == fileId; });
    std::erase_if(project.notes, [&](const WorkspaceNote& entry) { return entry.fileId == fileId; });
    std::erase_if(project.comparisons, [&](const WorkspaceComparison& entry) {
        return entry.fileAId == fileId || entry.fileBId == fileId;
    });
    if (project.session.selectedFileId == fileId) project.session.selectedFileId.clear();
}

}  // namespace

std::string makeWorkspaceId() {
    std::array<uint8_t, 16> bytes{};
    std::random_device random;
    for (auto& byte : bytes) byte = static_cast<uint8_t>(random());
    bytes[6] = static_cast<uint8_t>((bytes[6] & 0x0F) | 0x40);
    bytes[8] = static_cast<uint8_t>((bytes[8] & 0x3F) | 0x80);
    constexpr char hex[] = "0123456789abcdef";
    std::string id;
    id.reserve(36);
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) id.push_back('-');
        id.push_back(hex[bytes[i] >> 4]);
        id.push_back(hex[bytes[i] & 0x0F]);
    }
    return id;
}

std::string renderWorkspaceJson(const WorkspaceData& data) {
    Json root = Json::object();
    root.set("schema_version", static_cast<int64_t>(kWorkspaceSchemaVersion));
    root.set("last_active_project_id", data.lastActiveProjectId);
    Json projects = Json::array();
    for (const auto& project : data.projects) projects.push(projectToJson(project));
    root.set("projects", std::move(projects));
    const std::string payload = root.dump(-1);
    root.set("integrity_sha256", Sha256::hexDigest(std::span<const uint8_t>(
                                      reinterpret_cast<const uint8_t*>(payload.data()), payload.size())));
    return root.dump(2) + "\n";
}

WorkspaceLoadResult parseWorkspaceJson(const std::string& json) {
    WorkspaceLoadResult result;
    if (json.size() > kMaxWorkspaceBytes) {
        result.error = "Workspace metadata exceeds the maximum supported size.";
        return result;
    }
    const auto parsed = Json::parse(json);
    if (!parsed.value || !parsed.value->isObject()) {
        result.error = parsed.error.empty() ? "Workspace root must be a JSON object." : parsed.error;
        return result;
    }
    const Json& root = *parsed.value;
    const Json* version = root.find("schema_version");
    if (!version || version->type() != Json::Type::Int || version->asInt() < 1 ||
        static_cast<uint64_t>(version->asInt()) > kWorkspaceSchemaVersion) {
        result.error = "Workspace schema version is missing, invalid, or newer than this application supports.";
        return result;
    }
    const uint64_t schema = static_cast<uint64_t>(version->asInt());
    if (schema >= 2) {
        const Json* checksum = root.find("integrity_sha256");
        if (!checksum || !checksum->isString() || checksum->asString().size() != 64) {
            result.error = "Workspace integrity checksum is missing or malformed.";
            return result;
        }
        Json body = Json::object();
        for (const auto& [key, member] : root.members())
            if (key != "integrity_sha256") body.set(key, member);
        const std::string payload = body.dump(-1);
        const std::string actual = Sha256::hexDigest(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(payload.data()), payload.size()));
        if (actual != checksum->asString()) {
            result.error = "Workspace integrity check failed; the data was not loaded.";
            return result;
        }
    }
    result.data.schemaVersion = kWorkspaceSchemaVersion;
    result.data.lastActiveProjectId = value(root, "last_active_project_id");
    const Json* projects = root.find("projects");
    if (!projects || !projects->isArray() || projects->size() > kMaxProjects) {
        result.error = "Workspace project list is missing or exceeds the supported limit.";
        return result;
    }
    result.data.projects.reserve(projects->size());
    std::set<std::string> ids;
    for (const auto& item : projects->items()) {
        if (!item.isObject()) {
            result.error = "Workspace contains an invalid project record.";
            return result;
        }
        WorkspaceProject project;
        if (!readProject(item, &project) || !ids.insert(project.id).second) {
            result.error = "Workspace contains invalid, duplicated, or oversized project data.";
            return result;
        }
        result.data.projects.push_back(std::move(project));
    }
    if (!result.data.lastActiveProjectId.empty() && !ids.contains(result.data.lastActiveProjectId))
        result.data.lastActiveProjectId.clear();
    if (schema < kWorkspaceSchemaVersion) {
        result.warnings.push_back("Workspace metadata was migrated from schema version " +
                                  std::to_string(schema) + ".");
    }
    result.ok = true;
    return result;
}

WorkspaceLoadResult readWorkspace(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        if (ec) {
            WorkspaceLoadResult result;
            result.error = "Unable to inspect workspace metadata: " + ec.message();
            return result;
        }
        WorkspaceLoadResult result;
        result.ok = true;
        return result;
    }
    const uintmax_t size = std::filesystem::file_size(path, ec);
    if (ec || size > kMaxWorkspaceBytes) {
        WorkspaceLoadResult result;
        result.error = ec ? "Unable to read workspace metadata size: " + ec.message()
                          : "Workspace metadata exceeds the maximum supported size.";
        return result;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        WorkspaceLoadResult result;
        result.error = "Unable to open workspace metadata.";
        return result;
    }
    std::string json(static_cast<size_t>(size), '\0');
    input.read(json.data(), static_cast<std::streamsize>(json.size()));
    if (!input && !input.eof()) {
        WorkspaceLoadResult result;
        result.error = "Workspace metadata read failed.";
        return result;
    }
    if (static_cast<size_t>(input.gcount()) != json.size()) {
        WorkspaceLoadResult result;
        result.error = "Workspace metadata changed or was truncated while reading.";
        return result;
    }
    return parseWorkspaceJson(json);
}

bool writeWorkspace(const std::filesystem::path& path, const WorkspaceData& data, std::string* error) {
    if (data.projects.size() > kMaxProjects) {
        if (error) *error = "Workspace project count exceeds the supported limit.";
        return false;
    }
    const std::string json = renderWorkspaceJson(data);
    if (json.size() > kMaxWorkspaceBytes) {
        if (error) *error = "Workspace metadata exceeds the maximum supported size.";
        return false;
    }
    const auto validated = parseWorkspaceJson(json);
    if (!validated.ok) {
        if (error) *error = "Workspace data validation failed before saving: " + validated.error;
        return false;
    }
    const auto parent = path.parent_path();
    std::error_code ec;
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            if (error) *error = "Unable to create workspace directory: " + ec.message();
            return false;
        }
    }
    std::filesystem::path temporary = path;
    temporary += "." + makeWorkspaceId() + ".tmp";
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) {
            if (error) *error = "Unable to create temporary workspace file.";
            return false;
        }
        output.write(json.data(), static_cast<std::streamsize>(json.size()));
        output.flush();
        if (!output) {
            output.close();
            std::filesystem::remove(temporary, ec);
            if (error) *error = "Workspace metadata write failed.";
            return false;
        }
    }
#ifdef _WIN32
    if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const auto code = GetLastError();
        std::filesystem::remove(temporary, ec);
        if (error) *error = "Unable to atomically replace workspace metadata (Windows error " +
                            std::to_string(code) + ").";
        return false;
    }
#else
    std::filesystem::rename(temporary, path, ec);
    if (ec) {
        const std::string reason = ec.message();
        std::error_code cleanupError;
        std::filesystem::remove(temporary, cleanupError);
        if (error) *error = "Unable to atomically replace workspace metadata: " + reason;
        return false;
    }
#endif
    return true;
}

WorkspaceProject* findWorkspaceProject(WorkspaceData& data, const std::string& projectId) {
    const auto found = std::find_if(data.projects.begin(), data.projects.end(),
                                    [&](const WorkspaceProject& project) { return project.id == projectId; });
    return found == data.projects.end() ? nullptr : &*found;
}

const WorkspaceProject* findWorkspaceProject(const WorkspaceData& data, const std::string& projectId) {
    const auto found = std::find_if(data.projects.begin(), data.projects.end(),
                                    [&](const WorkspaceProject& project) { return project.id == projectId; });
    return found == data.projects.end() ? nullptr : &*found;
}

WorkspaceFile* findWorkspaceFile(WorkspaceProject& project, const std::string& fileId) {
    const auto found = std::find_if(project.files.begin(), project.files.end(),
                                    [&](const WorkspaceFile& file) { return file.id == fileId; });
    return found == project.files.end() ? nullptr : &*found;
}

const WorkspaceFile* findWorkspaceFile(const WorkspaceProject& project, const std::string& fileId) {
    const auto found = std::find_if(project.files.begin(), project.files.end(),
                                    [&](const WorkspaceFile& file) { return file.id == fileId; });
    return found == project.files.end() ? nullptr : &*found;
}

std::string createWorkspaceProject(WorkspaceData& data, std::string name,
                                   std::string description, std::string category) {
    if (name.empty() || name.size() > 512 || data.projects.size() >= kMaxProjects) return {};
    WorkspaceProject project;
    project.id = makeWorkspaceId();
    project.name = std::move(name);
    project.description = std::move(description);
    project.category = std::move(category);
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &time);
#else
    gmtime_r(&time, &utc);
#endif
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc);
    project.createdAt = buffer;
    project.modifiedAt = project.createdAt;
    data.lastActiveProjectId = project.id;
    data.projects.push_back(std::move(project));
    return data.projects.back().id;
}

bool renameWorkspaceProject(WorkspaceData& data, const std::string& projectId, std::string name) {
    auto* project = findWorkspaceProject(data, projectId);
    if (!project || name.empty() || name.size() > 512) return false;
    project->name = std::move(name);
    touch(*project);
    return true;
}

std::optional<std::string> duplicateWorkspaceProject(WorkspaceData& data,
                                                      const std::string& projectId,
                                                      std::string name) {
    const auto* original = findWorkspaceProject(data, projectId);
    if (!original || name.empty() || name.size() > 512 || data.projects.size() >= kMaxProjects)
        return std::nullopt;
    WorkspaceProject copy = *original;
    copy.id = makeWorkspaceId();
    copy.name = std::move(name);
    copy.createdAt = copy.modifiedAt;
    copy.version = 1;
    copy.session = {};
    for (auto& file : copy.files) file.id = makeWorkspaceId();
    auto remapFile = [&](std::string& fileId) {
        if (fileId.empty()) return;
        const auto oldId = fileId;
        const auto originalFile = std::find_if(original->files.begin(), original->files.end(),
                                               [&](const WorkspaceFile& file) { return file.id == oldId; });
        if (originalFile == original->files.end()) {
            fileId.clear();
            return;
        }
        const size_t index = static_cast<size_t>(std::distance(original->files.begin(), originalFile));
        fileId = copy.files[index].id;
    };
    for (auto& analysis : copy.analyses) {
        analysis.id = makeWorkspaceId();
        remapFile(analysis.fileId);
    }
    for (auto& bookmark : copy.bookmarks) {
        bookmark.id = makeWorkspaceId();
        remapFile(bookmark.fileId);
    }
    for (auto& note : copy.notes) {
        note.id = makeWorkspaceId();
        remapFile(note.fileId);
    }
    for (auto& comparison : copy.comparisons) {
        comparison.id = makeWorkspaceId();
        remapFile(comparison.fileAId);
        remapFile(comparison.fileBId);
    }
    touch(copy);
    const std::string id = copy.id;
    data.projects.push_back(std::move(copy));
    data.lastActiveProjectId = id;
    return id;
}

bool deleteWorkspaceProject(WorkspaceData& data, const std::string& projectId) {
    const auto found = std::find_if(data.projects.begin(), data.projects.end(),
                                    [&](const WorkspaceProject& project) { return project.id == projectId; });
    if (found == data.projects.end()) return false;
    data.projects.erase(found);
    if (data.lastActiveProjectId == projectId) data.lastActiveProjectId.clear();
    return true;
}

std::optional<std::string> addWorkspaceFile(WorkspaceProject& project, WorkspaceFile file) {
    if (file.path.empty() || file.sha256.empty() || project.files.size() >= kMaxFilesPerProject)
        return std::nullopt;
    const auto duplicate = std::find_if(project.files.begin(), project.files.end(), [&](const WorkspaceFile& item) {
        return item.sha256 == file.sha256;
    });
    if (duplicate != project.files.end()) return duplicate->id;
    if (file.id.empty()) file.id = makeWorkspaceId();
    project.files.push_back(std::move(file));
    touch(project);
    return project.files.back().id;
}

bool removeWorkspaceFile(WorkspaceProject& project, const std::string& fileId) {
    const auto found = std::find_if(project.files.begin(), project.files.end(),
                                    [&](const WorkspaceFile& file) { return file.id == fileId; });
    if (found == project.files.end()) return false;
    project.files.erase(found);
    removeFileOwnedEntries(project, fileId);
    touch(project);
    return true;
}

bool renameWorkspaceTag(WorkspaceProject& project, const std::string& oldName,
                        const std::string& newName) {
    if (oldName.empty() || newName.empty() || newName.size() > 256 ||
        std::any_of(project.tags.begin(), project.tags.end(),
                    [&](const WorkspaceTag& tag) { return tag.name == newName && tag.name != oldName; }))
        return false;
    const auto found = std::find_if(project.tags.begin(), project.tags.end(),
                                    [&](const WorkspaceTag& tag) { return tag.name == oldName; });
    if (found == project.tags.end()) return false;
    found->name = newName;
    auto replace = [&](std::vector<std::string>& tags) {
        for (auto& tag : tags) if (tag == oldName) tag = newName;
    };
    for (auto& file : project.files) replace(file.tags);
    for (auto& bookmark : project.bookmarks) replace(bookmark.tags);
    for (auto& note : project.notes) replace(note.tags);
    touch(project);
    return true;
}

bool deleteWorkspaceTag(WorkspaceProject& project, const std::string& name) {
    const auto oldSize = project.tags.size();
    std::erase_if(project.tags, [&](const WorkspaceTag& tag) { return tag.name == name; });
    if (oldSize == project.tags.size()) return false;
    auto remove = [&](std::vector<std::string>& tags) {
        std::erase(tags, name);
    };
    for (auto& file : project.files) remove(file.tags);
    for (auto& bookmark : project.bookmarks) remove(bookmark.tags);
    for (auto& note : project.notes) remove(note.tags);
    touch(project);
    return true;
}

}  // namespace xrl
