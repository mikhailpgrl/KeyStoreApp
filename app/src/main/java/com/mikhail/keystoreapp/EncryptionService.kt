package com.mikhail.keystoreapp

import android.os.Build
import com.mikhail.keystoreapp.CipherWrapper.Companion.TRANSFORMATION_ASYMMETRIC
import com.mikhail.keystoreapp.CipherWrapper.Companion.TRANSFORMATION_SYMMETRIC
import java.security.KeyStoreException
import javax.crypto.SecretKey

class EncryptionService(private val keyStoreWrapper: KeyStoreWrapper) {

    fun encryptWithSymmetricKey(keyAlias: String, data: String, password: String): String {
        val key: SecretKey = (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyStoreWrapper.getAndroidKeyStoreSymmetricKey(keyAlias, password)
        } else {
            keyStoreWrapper.getDefaultKeyStoreSymmetricKey(keyAlias, password)
        }) ?: throw KeyStoreException()
        return CipherWrapper(TRANSFORMATION_SYMMETRIC).encrypt(data, key, true)
    }

    fun decryptWithSymmetricKey(keyAlias: String, password: String, data: String): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (keyStoreWrapper.containsKey(keyAlias)) {
                val key = keyStoreWrapper.getAndroidKeyStoreSymmetricKey(keyAlias, password)
                CipherWrapper(TRANSFORMATION_SYMMETRIC).decrypt(data, key, true)
            } else {
                null
            }
        } else {
            val masterKey = keyStoreWrapper.getDefaultKeyStoreSymmetricKey(keyAlias, password)
            CipherWrapper(TRANSFORMATION_SYMMETRIC).decrypt(data, masterKey, true)
        }
    }

    fun encryptWithAsymmetricKey(keyAlias: String, data: String): String? {
        val key =
            keyStoreWrapper.getAndroidKeyStoreAsymmetricKeyPair(keyAlias)?.private
        return CipherWrapper(TRANSFORMATION_ASYMMETRIC).encrypt(data, key, false)
    }
}