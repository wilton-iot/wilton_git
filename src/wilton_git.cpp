/*
 * Copyright 2019, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   wilton_git.cpp
 * Author: alex
 *
 * Created on March 12, 2019, 3:19 PM
 */

#include "wilton/wilton_git.h"

#include <string>
#include <memory>
#include <utility>

#include "git2.h"

#include "staticlib/config.hpp"
#include "staticlib/io.hpp"
#include "staticlib/json.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/alloc.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/logging.hpp"

namespace { // anonymous

const std::string logger = std::string("wilton.git");

const std::string file_proto = std::string("file://");
const std::string ssh_proto = std::string("git+ssh://");
const std::string http_proto = std::string("http://");
const std::string https_proto = std::string("https://");

struct cb_payload {
    std::string username;
    std::string password;
    std::string ssh_pubkey;
    std::string ssh_privkey;
    bool https_cert_check = true;
    std::string branch_name;

    cb_payload(const std::string& user, const std::string& pass,
            const std::string& pubkey, const std::string& privkey,
            bool hcheck, const std::string& branch) :
    username(user.data(), user.length()),
    password(pass.data(), pass.length()),
    ssh_pubkey(pubkey.data(), pubkey.length()),
    ssh_privkey(privkey.data(), privkey.length()),
    https_cert_check(hcheck),
    branch_name(branch.data(), branch.length()) {}

    cb_payload(const cb_payload&) = delete;
    cb_payload& operator=(const cb_payload&) = delete;
};

std::pair<std::string, int> last_git_error() {
    auto msg = std::string();
    int code = -1;
    //auto gerr = git_error_last();
    auto gerr = giterr_last();
    if (nullptr != gerr) {
        if (nullptr != gerr->message) {
            msg.append(gerr->message);
        }
        code = gerr->klass;
    }
    return {msg, code};
}

int cred_cb(git_cred** out, const char* url, const char* user,
        unsigned int allowed_types, void* payload) {
    auto pl = reinterpret_cast<cb_payload*>(payload);
    auto url_str = std::string(nullptr != url ? url : "");
    auto user_str = std::string(nullptr != user ? user : "");
    if (sl::utils::starts_with(url_str, ssh_proto)) { // ssh
        if (!pl->ssh_pubkey.empty() && !pl->ssh_privkey.empty()) { // key auth
            return git_cred_ssh_key_new(out, user_str.c_str(), pl->ssh_pubkey.c_str(),
                    pl->ssh_privkey.c_str(), nullptr);
        } else { // user password auth
            if (GIT_CREDTYPE_USERNAME == allowed_types) { // asked for username
                if (!pl->username.empty()) {
                    return git_cred_username_new(out, pl->username.c_str());
                } else {
                    // 0 for success, < 0 to indicate an error,
                    // > 0 to indicate no credential was acquired
                    return 1;
                }
            } else { // asked for password
                return git_cred_userpass_plaintext_new(out,
                        user_str.c_str(), pl->password.c_str());
            }
        }
    } else { // https
        auto& user_to_pass = !user_str.empty() ? user_str : pl->username;
        return git_cred_userpass_plaintext_new(out, user_to_pass.c_str(), pl->password.c_str());
    }
}

int cert_cb(git_cert*, int valid, const char*, void* payload) {
    auto pl = reinterpret_cast<cb_payload*>(payload);
    if (pl->https_cert_check) {
        return valid;
    } else {
        return 0;
    }
}

void check_supported_protocol(const std::string& remote_url_str) {
    if (!(sl::utils::starts_with(remote_url_str, file_proto) ||
            sl::utils::starts_with(remote_url_str, ssh_proto) ||
            sl::utils::starts_with(remote_url_str, http_proto) ||
            sl::utils::starts_with(remote_url_str, https_proto))) {
        throw wilton::support::exception(TRACEMSG("Unsupported protocol specified," +
                " URL: [" + remote_url_str + "], supported protocols: [" +
                file_proto + ", " + ssh_proto + ", " + http_proto + ", " + https_proto + "]"));
    }
}

std::unique_ptr<cb_payload> create_payload(const std::string& remote_url_str, sl::io::span<const char> span) {
    auto json = sl::json::load(span);
    auto ruser = std::ref(sl::utils::empty_string());
    auto rpassword = std::ref(sl::utils::empty_string());
    auto rssh_pubkey = std::ref(sl::utils::empty_string());
    auto rssh_privkey = std::ref(sl::utils::empty_string());
    bool https_cert_check = true;
    auto rbranch = std::ref(sl::utils::empty_string());
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("username" == name) {
            ruser = fi.as_string_nonempty_or_throw(name);
        } else if ("password" == name) {
            rpassword = fi.as_string_nonempty_or_throw(name);
        } else if ("sshPublicKeyPath" == name) {
            rssh_pubkey = fi.as_string_nonempty_or_throw(name);
        } else if ("sshPrivateKeyPath" == name) {
            rssh_privkey = fi.as_string_nonempty_or_throw(name);
        } else if ("httpsCheckCertificate" == name) {
            https_cert_check = fi.as_bool_or_throw(name);
        } else if ("branch" == name) {
            rbranch = fi.as_string_nonempty_or_throw(name);
        } else {
            throw wilton::support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (sl::utils::starts_with(remote_url_str, "git+ssh:")) {
        if ((rssh_pubkey.get().empty() || rssh_privkey.get().empty()) && rpassword.get().empty()) {
            throw wilton::support::exception(TRACEMSG(
                "Either both 'sshPublicKeyPath' and 'sshPrivateKeyPath' or 'password'"
                " options must be specified for authentication over 'git+ssh' protocol"));
        }
    }
    return sl::support::make_unique<cb_payload>(
            ruser.get(), rpassword.get(),
            rssh_pubkey.get(), rssh_privkey.get(),
            https_cert_check, rbranch.get());
}

void checkout_remote_branch(const std::string& repo_path, git_repository* repo, const std::string& branch_name) {
    auto branch = !branch_name.empty() ? branch_name : "master";
    git_object* treeish = nullptr;
    auto rbranch = "origin/" + branch;
    auto tree_err = git_revparse_single(std::addressof(treeish), repo, rbranch.c_str());
    if (0 != tree_err) {
        auto pa = last_git_error();
        throw wilton::support::exception(TRACEMSG(
                "Remote branch not found," + 
                " branch: [" + rbranch + "]," +
                " path: [" + repo_path + "]," +
                " code: [" + sl::support::to_string(pa.second) + "]," +
                " message: [" + pa.first + "]"));
    }
    auto deferred_treeish = sl::support::defer([treeish]() STATICLIB_NOEXCEPT {
        git_object_free(treeish);
    });

    git_checkout_options copts;
    git_checkout_init_options(std::addressof(copts), GIT_CHECKOUT_OPTIONS_VERSION);
    copts.checkout_strategy = GIT_CHECKOUT_SAFE;
    auto checkout_err = git_checkout_tree(repo, treeish, std::addressof(copts));
    if (0 != checkout_err) {
        auto pa = last_git_error();
        throw wilton::support::exception(TRACEMSG(
                "Branch checkout error," + 
                " branch: [" + rbranch + "]," +
                " path: [" + repo_path + "]," +
                " code: [" + sl::support::to_string(pa.second) + "]," +
                " message: [" + pa.first + "]"));
    }

    auto ref = "refs/remotes/origin/" + branch;
    auto head_err = git_repository_set_head(repo, ref.c_str());
    if(0 != head_err) {
        auto pa = last_git_error();
        throw wilton::support::exception(TRACEMSG(
                "Branch set HEAD error," + 
                " branch: [" + ref + "]," +
                " path: [" + repo_path + "]," +
                " code: [" + sl::support::to_string(pa.second) + "]," +
                " message: [" + pa.first + "]"));
    }
}

} // namespace

char* wilton_git_initialize() {
    git_libgit2_init();
    return nullptr;
}

char* wilton_git_shutdown() {
    git_libgit2_shutdown();
    return nullptr;
}

char* wilton_git_clone(
        const char* remote_url,
        int remote_url_len,
        const char* dest_repo_path,
        int dest_repo_path_len,
        const char* options_json,
        int options_json_len) /* noexcept */ {
    if (nullptr == remote_url) return wilton::support::alloc_copy(TRACEMSG("Null 'remote_url' parameter specified"));
    if (!sl::support::is_uint16_positive(remote_url_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'remote_url_len' parameter specified: [" + sl::support::to_string(remote_url_len) + "]"));
    if (nullptr == dest_repo_path) return wilton::support::alloc_copy(TRACEMSG("Null 'dest_repo_path' parameter specified"));
    if (!sl::support::is_uint16_positive(dest_repo_path_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'dest_repo_path_len' parameter specified: [" + sl::support::to_string(dest_repo_path_len) + "]"));
    if (nullptr == options_json) return wilton::support::alloc_copy(TRACEMSG("Null 'options_json' parameter specified"));
    if (!sl::support::is_uint32_positive(options_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'options_json_len' parameter specified: [" + sl::support::to_string(options_json_len) + "]"));
    try {
        auto remote_url_str = std::string(remote_url, static_cast<uint16_t>(remote_url_len));
        auto dest_repo_path_str = std::string(dest_repo_path, static_cast<uint16_t>(dest_repo_path_len));

        // check protocol
        check_supported_protocol(remote_url_str);

        // parse options
        auto span = sl::io::make_span(options_json, options_json_len);
        auto payload = create_payload(remote_url_str, span);

        // prepare options
        git_clone_options opts;
        git_clone_init_options(std::addressof(opts), GIT_CLONE_OPTIONS_VERSION);
        opts.fetch_opts.callbacks.credentials = cred_cb;
        opts.fetch_opts.callbacks.certificate_check = cert_cb;
        opts.fetch_opts.callbacks.payload = reinterpret_cast<void*>(payload.get());
        // strip file proto (required for windows)
        if (sl::utils::starts_with(remote_url_str, file_proto)) {
            remote_url_str = remote_url_str.substr(file_proto.length());
        }

        // call libgit2
        git_repository* repo = nullptr;
        wilton::support::log_debug(logger, std::string() + "Cloning Git repo," +
                " URL: [" + remote_url_str + "] destination: [" + dest_repo_path_str + "] ...");
        auto err = git_clone(std::addressof(repo), remote_url_str.c_str(),
                dest_repo_path_str.c_str(), std::addressof(opts));
        if (0 != err) {
            auto pa = last_git_error();
            throw wilton::support::exception(TRACEMSG(
                    "Error cloning git repo," + 
                    " URL: [" + remote_url_str + "]," +
                    " destination: [" + dest_repo_path_str + "]," +
                    " code: [" + sl::support::to_string(pa.second) + "]," +
                    " message: [" + pa.first + "]"));
        }
        auto deferred_repo = sl::support::defer([repo]() STATICLIB_NOEXCEPT {
            git_repository_free(repo);
        });

        checkout_remote_branch(dest_repo_path_str, repo, payload->branch_name);

        wilton::support::log_debug(logger, "Git repo cloned successfully");

        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_git_pull(
        const char* repo_path,
        int repo_path_len,
        const char* options_json,
        int options_json_len) /* noexcept */ {
    if (nullptr == repo_path) return wilton::support::alloc_copy(TRACEMSG("Null 'repo_path' parameter specified"));
    if (!sl::support::is_uint16_positive(repo_path_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'repo_path_len' parameter specified: [" + sl::support::to_string(repo_path_len) + "]"));
    if (nullptr == options_json) return wilton::support::alloc_copy(TRACEMSG("Null 'options_json' parameter specified"));
    if (!sl::support::is_uint32_positive(options_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'options_json_len' parameter specified: [" + sl::support::to_string(options_json_len) + "]"));
    try {
        auto repo_path_str = std::string(repo_path, static_cast<uint16_t>(repo_path_len));
        wilton::support::log_debug(logger, std::string() + "Pulling Git repo," +
                " path: [" + repo_path_str + "] ...");

        // find out remote url
        git_repository* repo = nullptr;
        auto open_err = git_repository_open(std::addressof(repo), repo_path_str.c_str());
        if (0 != open_err) {
            auto pa = last_git_error();
            throw wilton::support::exception(TRACEMSG(
                    "Error opening git repo," + 
                    " path: [" + repo_path_str + "]," +
                    " code: [" + sl::support::to_string(pa.second) + "]," +
                    " message: [" + pa.first + "]"));
        }
        auto deferred_repo = sl::support::defer([repo]() STATICLIB_NOEXCEPT {
            git_repository_free(repo);
        });

        git_remote* remote = nullptr;
        auto lookup_err = git_remote_lookup(std::addressof(remote), repo, "origin");
        if (0 != lookup_err) {
            auto pa = last_git_error();
            throw wilton::support::exception(TRACEMSG(
                    "Remote 'origin' lookup error," + 
                    " path: [" + repo_path_str + "]," +
                    " code: [" + sl::support::to_string(pa.second) + "]," +
                    " message: [" + pa.first + "]"));
        }
        auto deferred_remote = sl::support::defer([remote]() STATICLIB_NOEXCEPT {
            git_remote_free(remote);
        });

        auto url_ptr = git_remote_url(remote);
        if (nullptr == url_ptr) {
            auto pa = last_git_error();
            throw wilton::support::exception(TRACEMSG(
                    "Remote 'origin' URL error," + 
                    " path: [" + repo_path_str + "]," +
                    " code: [" + sl::support::to_string(pa.second) + "]," +
                    " message: [" + pa.first + "]"));
        }
        auto url_read = std::string(url_ptr);
        auto url = std::string();
        if (!(sl::utils::starts_with(url_read, ssh_proto) ||
                sl::utils::starts_with(url_read, http_proto) ||
                sl::utils::starts_with(url_read, https_proto))) {
            url = file_proto + url_read;
        } else {
            url = url_read;
        }

        // check protocol
        check_supported_protocol(url);

        // parse options
        auto span = sl::io::make_span(options_json, options_json_len);
        auto payload = create_payload(url, span);

        // prepare options
        git_fetch_options opts;
        git_fetch_init_options(std::addressof(opts), GIT_FETCH_OPTIONS_VERSION);
        opts.callbacks.credentials = cred_cb;
        opts.callbacks.certificate_check = cert_cb;
        opts.callbacks.payload = reinterpret_cast<void*>(payload.get());
 
        // fetch
        auto fetch_err = git_remote_fetch(remote, nullptr, std::addressof(opts), nullptr);
        if (0 != fetch_err) {
            auto pa = last_git_error();
            throw wilton::support::exception(TRACEMSG(
                    "Remote repo fetch error," + 
                    " url: [" + url + "]," +
                    " path: [" + repo_path_str + "]," +
                    " code: [" + sl::support::to_string(pa.second) + "]," +
                    " message: [" + pa.first + "]"));
        }

        checkout_remote_branch(repo_path_str, repo, payload->branch_name);

        wilton::support::log_debug(logger, "Git repo pulled successfully");

        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}