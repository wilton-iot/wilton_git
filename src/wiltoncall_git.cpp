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
 * File:   wiltoncall_git.cpp
 * Author: alex
 *
 * Created on March 12, 2019, 3:23 PM
 */

#include <cstdint>
#include <memory>
#include <string>

#include "staticlib/config.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

#include "wilton/wilton.h"
#include "wilton/wiltoncall.h"
#include "wilton/wilton_git.h"

#include "wilton/support/buffer.hpp"
#include "wilton/support/registrar.hpp"

namespace wilton {
namespace git {

namespace { //anonymous

// initialized from wilton_module_init
std::shared_ptr<bool> shutdown_trigger() {
    static auto trigger = std::shared_ptr<bool>(new bool(true), [](bool* flag) {
        delete flag;
        wilton_git_shutdown();
    });
    return trigger;
}

} // namespace

support::buffer clone(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rurl = std::ref(sl::utils::empty_string());
    auto rrepo = std::ref(sl::utils::empty_string());
    auto options = std::string();
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("url" == name) {
            rurl = fi.as_string_nonempty_or_throw(name);
        } else if ("repo" == name) {
            rrepo = fi.as_string_nonempty_or_throw(name);
        } else if ("options" == name) {
            if (sl::json::type::object != fi.json_type()) {
                throw support::exception(TRACEMSG("Invalid non-object options specified," +
                        " type: [" + sl::json::stringify_json_type(fi.json_type()) + "]"));
            }
            options = fi.val().dumps();
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rurl.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'url' not specified"));
    if (rrepo.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'repo' not specified"));
    if (options.empty()) throw support::exception(TRACEMSG(
            "Required parameter 'options' not specified"));
    const std::string& url = rurl.get();
    const std::string& repo = rrepo.get();
    // prevent shutdown during the call
    auto trigger = shutdown_trigger();
    // call wilton
    char* err = wilton_git_clone(url.c_str(), static_cast<int>(url.length()),
            repo.c_str(), static_cast<int>(repo.length()),
            options.c_str(), static_cast<int>(options.length()));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::make_null_buffer();
}

support::buffer pull(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rrepo = std::ref(sl::utils::empty_string());
    auto rbranch = std::ref(sl::utils::empty_string());
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("repo" == name) {
            rrepo = fi.as_string_nonempty_or_throw(name);
        } else if ("branch" == name) {
            rbranch = fi.as_string_nonempty_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rrepo.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'repo' not specified"));
    if (rbranch.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'branch' not specified"));
    const std::string& repo = rrepo.get();
    const std::string& branch = rbranch.get();
    // prevent shutdown during the call
    auto trigger = shutdown_trigger();
    // call wilton
    char* err = wilton_git_pull(repo.c_str(), static_cast<int>(repo.length()),
            branch.c_str(), static_cast<int>(branch.length()));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::make_null_buffer();
}

} // namespace
}

extern "C" char* wilton_module_init() {
    try {
        auto err = wilton_git_initialize();
        if (nullptr != err) wilton::support::throw_wilton_error(err, TRACEMSG(err));

        wilton::git::shutdown_trigger();
        wilton::support::register_wiltoncall("git_clone", wilton::git::clone);
        wilton::support::register_wiltoncall("git_pull", wilton::git::pull);

        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}