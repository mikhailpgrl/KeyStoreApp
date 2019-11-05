package com.mikhail.keystoreapp

import com.mikhail.keystoreapp.CipherWrapper.Companion.TRANSFORMATION_SYMMETRIC

class EncryptionService {

    private val keyStoreWrapper = KeyStoreWrapper()

    fun encryptWithAndroidSymmetricKey(keyAlias: String, data: String): String {
        val key = keyStoreWrapper.generateAndroidKeyStoreSymmetricKey(keyAlias)
        return CipherWrapper(TRANSFORMATION_SYMMETRIC).encrypt(data, key, true)
    }

    fun decryptWithAndroidSymmetricKey(keyAlias: String, data: String): String? {
        return if (keyStoreWrapper.containsKey(keyAlias)) {
            val key = keyStoreWrapper.getAndroidKeyStoreSymmetricKey(keyAlias)
            CipherWrapper(TRANSFORMATION_SYMMETRIC).decrypt(data, key, true)
        } else {
            null
        }
    }
}