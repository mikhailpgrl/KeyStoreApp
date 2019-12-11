package com.mikhail.keystoreapp

import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.security.auth.x500.X500Principal


class KeyStoreWrapper(private val context: Context) {

    private val keyStore: KeyStore = createAndroidKeyStore()

    private val defaultKeyStoreFile = File(context.filesDir, "default_keystore")
    private val defaultKeyStore = createDefaultKeyStore()

    companion object {
        //private const val DEFAULT_KEY_STORE_NAME = "keys"
    }

    private fun createAndroidKeyStore(): KeyStore {
        // creates KeyStore instance with given type by traversing the list of registered security Providers, starting with the most preferred one
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null, null)
        return keyStore
    }

    private fun createDefaultKeyStore(password: String = ""): KeyStore {
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())

        if (!defaultKeyStoreFile.exists()) {
            keyStore.load(null, password.toCharArray())
        } else {
            keyStore.load(FileInputStream(defaultKeyStoreFile), password.toCharArray())
        }
        return keyStore
    }

    fun containsKey(keyAlias: String) = keyStore.containsAlias(keyAlias)

    fun getAndroidKeyStoreSymmetricKey(alias: String, keyPassword: String): SecretKey? =
        keyStore.getKey(alias, keyPassword.toCharArray()) as SecretKey?

    fun getAndroidKeyStoreAsymmetricKeyPair(alias: String): KeyPair? {
        val privateKey = keyStore.getKey(alias, null) as PrivateKey?
        val publicKey = keyStore.getCertificate(alias)?.publicKey

        return if (privateKey != null && publicKey != null) {
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    }


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
        val x = key.encoded.toString()
        defaultKeyStore.store(FileOutputStream(defaultKeyStoreFile), password.toCharArray())
        return key
    }

    @TargetApi(Build.VERSION_CODES.M)
    fun generateAndroidKeyStoreSymmetricKey(keyAlias: String): SecretKey {
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpecBuilder =
            KeyGenParameterSpec.Builder(
                keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            keyGenParameterSpecBuilder.setIsStrongBoxBacked(true)
        }

        keyGenerator.init(keyGenParameterSpecBuilder.build())
        return keyGenerator.generateKey()
    }


    fun generateAndroidKeyStoreAsymmetricKey(alias: String): KeyPair {
        val generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
        initGeneratorWithKeyPairGeneratorSpec(generator, alias)
        return generator.generateKeyPair()
    }

    private fun initGeneratorWithKeyPairGeneratorSpec(generator: KeyPairGenerator, alias: String) {
        val startDate = Calendar.getInstance()
        val endDate = Calendar.getInstance()
        endDate.add(Calendar.YEAR, 20)

        val builder = KeyPairGeneratorSpec.Builder(context)
            .setAlias(alias)
            .setSerialNumber(BigInteger.ONE)
            .setSubject(X500Principal("CN=${alias} CA Certificate"))
            .setStartDate(startDate.time)
            .setEndDate(endDate.time)

        generator.initialize(builder.build())
    }

}