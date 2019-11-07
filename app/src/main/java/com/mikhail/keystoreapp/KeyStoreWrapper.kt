package com.mikhail.keystoreapp

import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey


class KeyStoreWrapper(context: Context) {

    private val keyStore: KeyStore = createAndroidKeyStore()
    private val defaultKeyStoreFile = File(context.filesDir, DEFAULT_KEY_STORE_NAME)

    companion object {
        private const val DEFAULT_KEY_STORE_NAME = "keys"
    }

    fun createAndroidKeyStore(): KeyStore {
        // creates KeyStore instance with given type by traversing the list of registered security Providers, starting with the most preferred one
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore
    }

    fun containsKey(keyAlias: String) = keyStore.containsAlias(keyAlias)

    fun getAndroidKeyStoreSymmetricKey(alias: String): SecretKey? =
        keyStore.getKey(alias, null) as SecretKey?

    fun removeAndroidKeyStoreKey(alias: String) = keyStore.deleteEntry(alias)

    fun generateKeyStoreSymmetricKey(keyAlias: String, password: String): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        val key = keyGenerator.generateKey()
        val keyEntry = KeyStore.SecretKeyEntry(key)
        keyStore.setEntry(keyAlias, keyEntry, KeyStore.PasswordProtection(password.toCharArray()))
        keyStore.store(FileOutputStream(defaultKeyStoreFile), password.toCharArray())
        return key
    }

    @TargetApi(Build.VERSION_CODES.M)
    fun generateAndroidKeyStoreSymmetricKey(keyAlias: String): SecretKey {
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build()
        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

}