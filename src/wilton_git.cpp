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
    std::string ssh_pubkey;
    std::string ssh_privkey;
    bool https_cert_check = true;
    std::string https_username;
    std::string https_password;

    cb_payload(const std::string& pubkey, const std::string& privkey,
            bool check, const std::string& huser, const std::string& hpass) :
    ssh_pubkey(pubkey.data(), pubkey.length()),
    ssh_privkey(privkey.data(), privkey.length()),
    https_cert_check(check),
    https_username(huser.data(), huser.length()),
    https_password(hpass.data(), hpass.length()) { }

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

int cred_cb(git_cred** out, const char* url, const char* user, unsigned int, void* payload) {
    auto pl = reinterpret_cast<cb_payload*>(payload);
    auto url_str = std::string(nullptr != url ? url : "");
    auto user_str = std::string(nullptr != user ? user : "");
    if (sl::utils::starts_with(url_str, ssh_proto)) {
        return git_cred_ssh_key_new(out, user_str.c_str(), pl->ssh_pubkey.c_str(),
                pl->ssh_privkey.c_str(), nullptr);
    } else {
        auto& user_to_pass = !pl->https_username.empty() ? pl->https_username : user_str;
        return git_cred_userpass_plaintext_new(out,
                user_to_pass.c_str(), pl->https_password.c_str());
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
        if (!(sl::utils::starts_with(remote_url_str, file_proto) ||
                sl::utils::starts_with(remote_url_str, ssh_proto) ||
                sl::utils::starts_with(remote_url_str, http_proto) ||
                sl::utils::starts_with(remote_url_str, https_proto))) {
            throw wilton::support::exception(TRACEMSG("Unsupported protocol specified," +
                    " URL: [" + remote_url_str + "], supported protocols: [" +
                    file_proto + ", " + ssh_proto + ", " + http_proto + ", " + https_proto + "]"));
        }

        // parse options
        auto span = sl::io::make_span(options_json, options_json_len);
        auto json = sl::json::load(span);
        auto rssh_pubkey = std::ref(sl::utils::empty_string());
        auto rssh_privkey = std::ref(sl::utils::empty_string());
        bool https_cert_check = true;
        auto rhttps_user = std::ref(sl::utils::empty_string());
        auto rhttps_password = std::ref(sl::utils::empty_string());
        for (const sl::json::field& fi : json.as_object()) {
            auto& name = fi.name();
            if ("sshPublicKeyPath" == name) {
                rssh_pubkey = fi.as_string_nonempty_or_throw(name);
            } else if ("sshPrivateKeyPath" == name) {
                rssh_privkey = fi.as_string_nonempty_or_throw(name);
            } else if ("httpsCheckCertificate" == name) {
                https_cert_check = fi.as_bool_or_throw(name);
            } else if ("httpsUser" == name) {
                rhttps_user = fi.as_string_nonempty_or_throw(name);
            } else if ("httpsPassword" == name) {
                rhttps_password = fi.as_string_nonempty_or_throw(name);
            } else {
                throw wilton::support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
            }
        }
        if (sl::utils::starts_with(remote_url_str, "git+ssh:")) {
            if (rssh_pubkey.get().empty()) throw wilton::support::exception(TRACEMSG(
                    "Required parameter 'options.sshPublicKeyPath' not specified"));
            if (rssh_privkey.get().empty()) throw wilton::support::exception(TRACEMSG(
                    "Required parameter 'options.sshPrivateKeyPath' not specified"));
        }
        auto payload = sl::support::make_unique<cb_payload>(
                rssh_pubkey.get(), rssh_privkey.get(),
                https_cert_check, rhttps_user.get(), rhttps_password.get());

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
        if (0 == err) {
            wilton::support::log_debug(logger, "Git repo cloned successfully");
            git_repository_free(repo);
            return nullptr;
        } else {
            auto pa = last_git_error();
            throw wilton::support::exception(TRACEMSG(
                    "Error cloning git repo," + 
                    " URL: [" + remote_url_str + "]," +
                    " destination: [" + dest_repo_path_str + "]," +
                    " code: [" + sl::support::to_string(pa.second) + "]," +
                    " message: [" + pa.first + "]"));
        }
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_git_pull(
        const char* repo_path,
        int repo_path_len,
        const char* branch_name,
        int branch_name_len) /* noexcept */ {
    (void) repo_path;
    (void) repo_path_len;
    (void) branch_name;
    (void) branch_name_len;
    return nullptr;
}