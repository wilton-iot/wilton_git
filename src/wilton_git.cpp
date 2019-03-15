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

#include "git2.h"

#include "wilton/support/logging.hpp"

namespace { // anonymous

const std::string logger = std::string("wilton.git");

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
        int dest_repo_path_len) /* noexcept */ {
    (void) remote_url;
    (void) remote_url_len;
    (void) dest_repo_path;
    (void) dest_repo_path_len;
    return nullptr;
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