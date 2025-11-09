/*
 * Copyright (c) 2019, The Android Open Source Project
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

#define LOG_TAG "OemNetd"
#include <log/log.h>
#include "OemNetdListener.h"
#include "NetdConstants.h"
#include <android-base/stringprintf.h>

namespace com {
namespace android {
namespace internal {
namespace net {

::android::sp<::android::Binder> OemNetdListener::getListener() {
    // Thread-safe initialization.
    static ::android::sp<OemNetdListener> listener = ::android::sp<OemNetdListener>::make();
    static ::android::sp<::android::Binder> sBinder = ::android::Interface::asBinder(listener);
    return sBinder;
}

::android::binder::Status OemNetdListener::isAlive(bool* alive) {
    *alive = true;
    return ::android::binder::Status::ok();
}

::android::binder::Status OemNetdListener::registerOemUnsolicitedEventListener(
    const ::android::sp<IOemNetdUnsolicitedEventListener>& listener) {
    registerOemUnsolicitedEventListenerInternal(listener);
    listener->onRegistered();
    return ::android::binder::Status::ok();
}

void OemNetdListener::registerOemUnsolicitedEventListenerInternal(
    const ::android::sp<IOemNetdUnsolicitedEventListener>& listener) {
    std::lock_guard lock(mOemUnsolicitedMutex);

    // Create the death listener.
    class DeathRecipient : public ::android::Binder::DeathRecipient {
    public:
        DeathRecipient(OemNetdListener* oemNetdListener,
                       ::android::sp<IOemNetdUnsolicitedEventListener> listener)
              : mOemNetdListener(oemNetdListener), mListener(std::move(listener)) {}
        ~DeathRecipient() override = default;

        void binderDied(const ::android::wp<::android::Binder>& /* who */) override {
            mOemNetdListener->unregisterOemUnsolicitedEventListenerInternal(mListener);
        }

    private:
        OemNetdListener* mOemNetdListener;
        ::android::sp<IOemNetdUnsolicitedEventListener> mListener;
    };

    ::android::sp<::android::Binder::DeathRecipient> deathRecipient =
        new DeathRecipient(this, listener);
    ::android::Interface::asBinder(listener)->linkToDeath(deathRecipient);
    mOemUnsolicitedMap.insert({listener, deathRecipient});
}

void OemNetdListener::unregisterOemUnsolicitedEventListenerInternal(
    const ::android::sp<IOemNetdUnsolicitedEventListener>& listener) {
    std::lock_guard lock(mOemUnsolicitedMutex);
    mOemUnsolicitedMap.erase(listener);
}

std::string stringPrintf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    std::string result;
    ::android::base::StringAppendV(&result, fmt, ap);
    va_end(ap);
    return result;
}

::android::String16 set_iptables_rule(int v4v6, int type, ::android::String16 rules) {
    // iptables target
    const char* target = (v4v6 == 0) ? "v4" : (v4v6 == 1) ? "v6" : "v4v6";
    const char* table = (type == 0) ? "filter" : (type == 1) ? "nat" : "mangle";

    std::string command = stringPrintf(
        "%s\n%s\nCOMMIT\n",
        "table " + std::string(table),
        ::android::String8(rules).string()
    );
    ALOGV("set_iptables_rules:target=%d,type=%d, rules=%s", v4v6, type, command.c_str());
    int ret = execIptablesRestore(target, command.c_str());
    if (ret != 0) {
        ALOGE("Failed to set iptables rules: %s", strerror(errno));
        return ::android::String16("error_setting_iptables_rules");
    }
    ALOGI("Successfully set iptables rules: %s", command.c_str());
    return ::android::String16("iptables_rules_set_successfully");
}

::android::binder::Status OemNetdListener::set_iptables_rules(int v4v6, int type,
                                                             const ::android::String16& rules,
                                                             ::android::String16* result) {
    *result = set_iptables_rule(v4v6, type, rules);
    return ::android::binder::Status::ok();
}

} // namespace net
} // namespace internal
} // namespace android
} // namespace com
