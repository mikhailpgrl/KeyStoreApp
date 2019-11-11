package com.mikhail.keystoreapp

import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey


class KeyStoreWrapper(context: Context) {

    private val keyStore: KeyStore = createAndroidKeyStore()

    private val defaultKeyStoreFile = File(context.filesDir, "default_keystore")
    private val defaultKeyStore = createDefaultKeyStore()

    companion object {
        //private const val DEFAULT_KEY_STORE_NAME = "keys"
    }

    private fun createAndroidKeyStore(): KeyStore {
        // creates KeyStore instance with given type by traversing the list of registered security Providers, starting with the most preferred one
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore
    }

    private fun createDefaultKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())

        if (!defaultKeyStoreFile.exists()) {
            keyStore.load(null)
        } else {
            keyStore.load(FileInputStream(defaultKeyStoreFile), null)
        }
        return keyStore
    }

    fun containsKey(keyAlias: String) = keyStore.containsAlias(keyAlias)

    fun getAndroidKeyStoreSymmetricKey(alias: String): SecretKey? =
        keyStore.getKey(alias, null) as SecretKey?

    fun getDefaultKeyStoreSymmetricKey(alias: String, keyPassword: String): SecretKey? {
        return try {
            defaultKeyStore.getKey(alias, keyPassword.toCharArray()) as SecretKey
        } catch (e: UnrecoverableKeyException) {
            null
        }
    }

    fun removeAndroidKeyStoreKey(alias: String) = keyStore.deleteEntry(alias)

    fun generateKeyStoreSymmetricKey(keyAlias: String, password: String): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        val key = keyGenerator.generateKey()
        val keyEntry = KeyStore.SecretKeyEntry(key)
        defaultKeyStore.setEntry(
            keyAlias,
            keyEntry,
            KeyStore.PasswordProtection(password.toCharArray())
        )
        defaultKeyStore.store(FileOutputStream(defaultKeyStoreFile), password.toCharArray())
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