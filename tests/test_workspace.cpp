#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iterator>

#include "xrl/workspace.hpp"

using namespace xrl;

namespace {

std::filesystem::path testDirectory() {
    const auto path = std::filesystem::temp_directory_path() / ("xrl-workspace-" + makeWorkspaceId());
    std::filesystem::create_directories(path);
    return path;
}

}  // namespace

TEST(Workspace, PersistsProjectsFilesNotesBookmarksHistoryComparisonsAndSession) {
    const auto directory = testDirectory();
    const auto file = directory / "workspace.json";
    WorkspaceData data;
    const std::string projectId = createWorkspaceProject(data, "Sample investigation", "Notes", "Research");
    auto* project = findWorkspaceProject(data, projectId);
    ASSERT_NE(project, nullptr);
    WorkspaceFile binary;
    binary.path = "/tmp/sample.bin";
    binary.sha256 = "0123456789abcdef";
    binary.format = "ELF";
    binary.architecture = "x86-64";
    binary.size = 0x100000001ull;
    const auto fileId = addWorkspaceFile(*project, binary);
    ASSERT_TRUE(fileId);
    project->session.selectedFileId = *fileId;
    project->session.activePage = 7;
    project->session.selectedAddress = UINT64_MAX;
    project->session.selectedFunction = 0x401000;
    project->tags.push_back({"Needs Review", "#f0a000"});
    project->files.front().tags.push_back("Needs Review");
    project->notes.push_back({makeWorkspaceId(), "file", *fileId, binary.sha256,
                              "Analyst note", "**Potential table**", "2026-10-31T12:00:00Z",
                              "2026-10-31T12:00:00Z", 0x401020, {"Needs Review"}});
    project->bookmarks.push_back({makeWorkspaceId(), *fileId, binary.sha256, "Entry",
                                  "Investigate the entry point", "virtual-address", 0x401000,
                                  0x1000, "2026-10-31T12:00:00Z", {"Needs Review"}});
    project->analyses.push_back({makeWorkspaceId(), "strings", *fileId, binary.sha256,
                                 "2026-10-31T12:00:00Z", "0.1.0", "complete", "12 strings",
                                 "{\"count\":12}"});
    project->comparisons.push_back({makeWorkspaceId(), *fileId, binary.sha256, "other-file",
                                    "fedcba9876543210", "2026-10-31T12:00:00Z", "2 changed regions",
                                    "{\"diffs\":2}"});
    data.lastActiveProjectId = projectId;

    std::string error;
    ASSERT_TRUE(writeWorkspace(file, data, &error)) << error;
    const auto loaded = readWorkspace(file);
    ASSERT_TRUE(loaded.ok) << loaded.error;
    ASSERT_EQ(loaded.data.projects.size(), 1u);
    const auto& restored = loaded.data.projects.front();
    EXPECT_EQ(restored.name, "Sample investigation");
    ASSERT_EQ(restored.files.size(), 1u);
    EXPECT_EQ(restored.files.front().size, 0x100000001ull);
    EXPECT_EQ(restored.session.selectedAddress, UINT64_MAX);
    ASSERT_EQ(restored.notes.size(), 1u);
    EXPECT_EQ(restored.notes.front().markdown, "**Potential table**");
    ASSERT_EQ(restored.bookmarks.size(), 1u);
    EXPECT_EQ(restored.bookmarks.front().fileOffset, 0x1000u);
    ASSERT_EQ(restored.analyses.size(), 1u);
    EXPECT_EQ(restored.analyses.front().reportJson, "{\"count\":12}");
    ASSERT_EQ(restored.comparisons.size(), 1u);
    EXPECT_EQ(restored.comparisons.front().fileBHash, "fedcba9876543210");
    EXPECT_EQ(loaded.data.lastActiveProjectId, projectId);

    std::ifstream saved(file, std::ios::binary);
    std::string tampered((std::istreambuf_iterator<char>(saved)), std::istreambuf_iterator<char>());
    const auto namePosition = tampered.find("Sample investigation");
    ASSERT_NE(namePosition, std::string::npos);
    tampered[namePosition] = 'X';
    EXPECT_NE(parseWorkspaceJson(tampered).error.find("integrity check failed"), std::string::npos);
    std::filesystem::remove_all(directory);
}

TEST(Workspace, CreatesDuplicatesAndDeletesWithoutRemovingSourceFiles) {
    WorkspaceData data;
    const std::string projectId = createWorkspaceProject(data, "Original");
    auto* project = findWorkspaceProject(data, projectId);
    WorkspaceFile file;
    file.path = "/user/source.bin";
    file.sha256 = "same-binary-hash";
    const auto fileId = addWorkspaceFile(*project, file);
    ASSERT_TRUE(fileId);
    WorkspaceFile duplicate = file;
    duplicate.path = "/another/copy.bin";
    EXPECT_EQ(addWorkspaceFile(*project, duplicate), fileId);
    project->notes.push_back({makeWorkspaceId(), "file", *fileId, file.sha256,
                              "Note", "Keep this", "now", "now", {}, {}});
    const auto copyId = duplicateWorkspaceProject(data, projectId, "Copy");
    ASSERT_TRUE(copyId);
    const auto* copy = findWorkspaceProject(data, *copyId);
    ASSERT_NE(copy, nullptr);
    ASSERT_EQ(copy->files.size(), 1u);
    EXPECT_NE(copy->files.front().id, *fileId);
    EXPECT_EQ(copy->files.front().path, file.path);
    EXPECT_EQ(copy->notes.front().fileId, copy->files.front().id);
    EXPECT_TRUE(deleteWorkspaceProject(data, projectId));
    EXPECT_NE(findWorkspaceProject(data, *copyId), nullptr);
}

TEST(Workspace, TagManagementPropagatesAcrossProjectObjects) {
    WorkspaceProject project;
    project.id = makeWorkspaceId();
    project.name = "Tags";
    project.tags.push_back({"Review", "#ffffff"});
    project.files.push_back({makeWorkspaceId(), "/tmp/a", "hash", "ELF", "x86", 1, {"Review"}});
    project.bookmarks.push_back({makeWorkspaceId(), {}, {}, "mark", {}, {}, {}, {}, {}, {"Review"}});
    project.notes.push_back({makeWorkspaceId(), {}, {}, {}, "note", {}, {}, {}, {}, {"Review"}});
    EXPECT_TRUE(renameWorkspaceTag(project, "Review", "Investigate"));
    EXPECT_EQ(project.files.front().tags.front(), "Investigate");
    EXPECT_EQ(project.bookmarks.front().tags.front(), "Investigate");
    EXPECT_EQ(project.notes.front().tags.front(), "Investigate");
    EXPECT_TRUE(deleteWorkspaceTag(project, "Investigate"));
    EXPECT_TRUE(project.files.front().tags.empty());
}

TEST(Workspace, MigratesOlderSchemaAndRejectsCorruptOrFutureData) {
    const std::string oldWorkspace =
        R"({"schema_version":1,"last_active_project_id":"p","projects":[{"id":"p","name":"Old project"}]})";
    const auto migrated = parseWorkspaceJson(oldWorkspace);
    ASSERT_TRUE(migrated.ok) << migrated.error;
    EXPECT_EQ(migrated.data.schemaVersion, kWorkspaceSchemaVersion);
    ASSERT_EQ(migrated.warnings.size(), 1u);
    EXPECT_TRUE(migrated.data.projects.front().files.empty());

    EXPECT_FALSE(parseWorkspaceJson(R"({"schema_version":99,"projects":[]})").ok);
    EXPECT_FALSE(parseWorkspaceJson(R"({"schema_version":2,"projects":[{"id":"x","name":"x","analyses":[{"id":"a","report_json":"not json"}]}]})").ok);
    EXPECT_FALSE(parseWorkspaceJson("{not-json").ok);
}

TEST(Workspace, AtomicWriteFailureKeepsExistingDirectoryAndReportsError) {
    const auto directory = testDirectory();
    WorkspaceData data;
    const std::string id = createWorkspaceProject(data, "Project");
    ASSERT_FALSE(id.empty());
    std::string error;
    EXPECT_FALSE(writeWorkspace(directory, data, &error));
    EXPECT_FALSE(error.empty());
    EXPECT_TRUE(std::filesystem::is_directory(directory));
    std::filesystem::remove_all(directory);
}
