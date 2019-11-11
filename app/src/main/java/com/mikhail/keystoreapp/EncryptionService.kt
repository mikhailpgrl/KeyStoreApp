package com.mikhail.keystoreapp

import android.content.Context
import android.os.Build
import com.mikhail.keystoreapp.CipherWrapper.Companion.TRANSFORMATION_SYMMETRIC
import javax.crypto.SecretKey

class EncryptionService(context: Context) {

    private val keyStoreWrapper = KeyStoreWrapper(context)

    fun encryptWithSymmetricKey(keyAlias: String, data: String, password: String): String {
        val key: SecretKey = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyStoreWrapper.generateAndroidKeyStoreSymmetricKey(keyAlias)
        } else {
            keyStoreWrapper.generateKeyStoreSymmetricKey(keyAlias, password)
        }
        return CipherWrapper(TRANSFORMATION_SYMMETRIC).encrypt(data, key, true)
    }

    fun decryptWithSymmetricKey(keyAlias: String, password: String, data: String): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (keyStoreWrapper.containsKey(keyAlias)) {
                val key = keyStoreWrapper.getAndroidKeyStoreSymmetricKey(keyAlias)
                CipherWrapper(TRANSFORMATION_SYMMETRIC).decrypt(data, key, true)
            } else {
                null
            }
        } else {
            val masterKey = keyStoreWrapper.getDefaultKeyStoreSymmetricKey(keyAlias, password)
            CipherWrapper(TRANSFORMATION_SYMMETRIC).decrypt(data, masterKey, true)
        }

    }
}