// SPDX-License-Identifier: AGPL-3.0-only

package io.decerter.decerter_flutter

import io.flutter.embedding.android.FlutterActivity

// am start -S -n io.decerter.decerter_flutter/.MainActivity --es url … --es ca … --es id …: the extras become main's arguments
class MainActivity : FlutterActivity() {
    override fun getDartEntrypointArgs(): List<String> {
        return listOf(intent.getStringExtra("url") ?: "", intent.getStringExtra("ca") ?: "", intent.getStringExtra("id") ?: "")
    }
}
