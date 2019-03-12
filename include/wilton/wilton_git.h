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
 * File:   wilton_git.h
 * Author: alex
 *
 * Created on March 12, 2019, 2:52 PM
 */

#ifndef WILTON_GIT_H
#define WILTON_GIT_H

#ifdef __cplusplus
extern "C" {
#endif

char* wilton_git_initialize();

char* wilton_git_clone(
        const char* remote_url,
        int remote_url_len,
        const char* dest_repo_path,
        int dest_repo_path_len);

char* wilton_git_pull(
        const char* repo_path,
        int repo_path_len,
        const char* branch_name,
        int branch_name_len);

#ifdef __cplusplus
}
#endif

#endif /* WILTON_GIT_H */

