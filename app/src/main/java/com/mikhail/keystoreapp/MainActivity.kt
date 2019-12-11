package com.mikhail.keystoreapp

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    companion object {
        const val KEY_ALIAS = "testKey"
        const val PASSWORD = "password"
    }

    private val keyguardManager: KeyguardManager by lazy {
        applicationContext.getSystemService(
            Context.KEYGUARD_SERVICE
        ) as KeyguardManager
    }

    private val keyStoreWrapper by lazy { KeyStoreWrapper(this) }
    private val encryptionService by lazy { EncryptionService(keyStoreWrapper) }

    private lateinit var textToEncrypt: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        if (!isDeviceSecure()) {
            Toast.makeText(this, "Device is not secured", Toast.LENGTH_SHORT).show()
        }

        if (hasMarshmallow()) {
            keyStoreWrapper.generateAndroidKeyStoreSymmetricKey(KEY_ALIAS)
        } else {
            keyStoreWrapper.generateKeyStoreSymmetricKey(KEY_ALIAS, PASSWORD)
        }

        encryptData.setOnClickListener {
            textToEncrypt = dataToEncrypt.text.toString()
            encryptedData.text =
                encryptionService.encryptWithSymmetricKey(
                    KEY_ALIAS,
                    textToEncrypt,
                    PASSWORD
                )
        }

        decryptData.setOnClickListener {
            if (::textToEncrypt.isInitialized)
                decryptedData.text =
                    encryptionService.decryptWithSymmetricKey(
                        KEY_ALIAS,
                        PASSWORD,
                        encryptedData.text.toString()
                    )

        }

        // Lance exception pour la clé RSA
        // javax.crypto.IllegalBlockSizeException: input must be under 256 bytes
        encryptWithRSA.setOnClickListener {
            var data = ""
            (1..10).map { "a" }.forEach { data += it }
            keyStoreWrapper.generateAndroidKeyStoreAsymmetricKey(KEY_ALIAS)
            encryptionService.encryptWithAsymmetricKey(KEY_ALIAS, data)
        }

    }

    private fun isDeviceSecure(): Boolean =
        if (hasMarshmallow()) keyguardManager.isDeviceSecure else keyguardManager.isKeyguardSecure


    private fun hasMarshmallow() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M

}
