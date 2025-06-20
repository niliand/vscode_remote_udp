#ifndef _GIT_HPP_
#define _GIT_HPP_

#include <cstdint>
#include <git2.h>
#include <vector>

struct StatusItem {
    std::string path;
    uint8_t type;
};

enum GitFileStatus { ADDED, MODIFIED, DELETED };

bool git_init() {
    git_libgit2_init();
    return true;
}

std::vector<StatusItem> git_get_status(const std::string &path) {
    git_repository *repo = nullptr;
    git_status_list *status_list = nullptr;
    const char *repo_path = path.c_str();
    std::vector<StatusItem> res;

    do {
        int error = git_repository_open(&repo, repo_path);
        if (error < 0) {
            const git_error *e = git_error_last();
            std::cerr << "Error opening repository '" << repo_path << "': " << e->message
                      << std::endl;
            break;
        }

        git_status_options status_opts = GIT_STATUS_OPTIONS_INIT;
        error = git_status_list_new(&status_list, repo, &status_opts);
        if (error < 0) {
            const git_error *e = git_error_last();
            std::cerr << "Error getting status list: " << e->message << std::endl;
            break;
        }

        size_t status_count = git_status_list_entrycount(status_list);

        for (size_t i = 0; i < status_count; ++i) {
            const git_status_entry *s = git_status_byindex(status_list, i);
            const char *fpath = nullptr;

            if (s->head_to_index && s->head_to_index->new_file.path) {
                fpath = s->head_to_index->new_file.path;
            } else if (s->index_to_workdir && s->index_to_workdir->new_file.path) {
                fpath = s->index_to_workdir->new_file.path;
            } else {
                std::cerr << "Unknown Path (this shouldn't happen often)\n";
                continue;
            }

            unsigned int flags = s->status;
            std::cout << i << ": " << fpath << ", flags=" << s->status << "\n";

            if (fpath) {
                std::string filepath(fpath);
                if (flags & (GIT_STATUS_INDEX_NEW | GIT_STATUS_WT_NEW)) {
                    res.push_back({filepath, GitFileStatus::ADDED});
                }
                if (flags & (GIT_STATUS_INDEX_MODIFIED | GIT_STATUS_WT_MODIFIED)) {
                    res.push_back({filepath, GitFileStatus::MODIFIED});
                }
                if (flags & (GIT_STATUS_INDEX_DELETED | GIT_STATUS_WT_DELETED)) {
                    res.push_back({filepath, GitFileStatus::DELETED});
                }
            }
        }

    } while (false);

    if (status_list) {
        git_status_list_free(status_list);
    }
    if (repo) {
        git_repository_free(repo);
    }

    return res;
}

std::vector<char> git_get_unmodified_file(const char *repo_path, const char *file_path) {

    int error;
    git_repository *repo = nullptr;
    git_reference *head_ref = nullptr;
    git_commit *head_commit = nullptr;
    git_tree *tree = nullptr;
    git_tree_entry *tree_entry = nullptr;
    git_blob *blob = nullptr;

    do {
        // 1. Open the repository
        error = git_repository_open(&repo, repo_path);
        if (error < 0) {
            const git_error *e = git_error_last();
            std::cerr << "Error opening repository '" << repo_path << "': " << e->message
                      << std::endl;
            break;
        }

        // 2. Resolve HEAD (the current branch reference)
        error = git_repository_head(&head_ref, repo);
        if (error < 0) {
            const git_error *e = git_error_last();
            std::cerr << "Getting HEAD reference '" << repo_path << "': " << e->message
                      << std::endl;
            break;
        }

        // 3. Get the commit object that HEAD points to
        error = git_reference_peel(reinterpret_cast<git_object **>(&head_commit), head_ref,
                                   GIT_OBJECT_COMMIT);
        if (error < 0) {
            const git_error *e = git_error_last();
            std::cerr << "Peeling HEAD reference to commit '" << repo_path << "': " << e->message
                      << std::endl;
            break;
        }

        // 4. Get the tree object associated with the HEAD commit
        error = git_commit_tree(&tree, head_commit);
        if (error < 0) {
            const git_error *e = git_error_last();
            std::cerr << "Getting tree from HEAD commit '" << repo_path << "': " << e->message
                      << std::endl;
            break;
        }

        // 5. Look up the file within the tree
        error = git_tree_entry_bypath(&tree_entry, tree, file_path);
        if (error < 0) {
            const git_error *e = git_error_last();
            std::cerr << "Error: File '" << file_path
                      << "' not found in HEAD commit: " << e->message << std::endl;
            break;
        }

        error = git_blob_lookup(&blob, repo, git_tree_entry_id(tree_entry));
        if (error < 0) {
            const git_error *e = git_error_last();
            std::cerr << "Looking up blob object from tree entry '" << repo_path
                      << "': " << e->message << std::endl;
            break;
        }

        // 7. Get the content of the blob
        const char *content = (const char *)git_blob_rawcontent(blob);
        git_off_t content_len = git_blob_rawsize(blob);

        std::vector<char> file_data(content, content + content_len);
        return file_data;

    } while (false);

    // Free all allocated libgit2 objects in reverse order of allocation
    if (blob) {
        git_blob_free(blob);
    }
    if (tree_entry) {
        git_tree_entry_free(tree_entry);
    }
    if (tree) {
        git_tree_free(tree);
    }
    if (head_commit) {
        git_commit_free(head_commit);
    }
    if (head_ref) {
        git_reference_free(head_ref);
    }
    if (repo) {
        git_repository_free(repo);
    }

    return {};
}

#endif //_GIT_HPP_