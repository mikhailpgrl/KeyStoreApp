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
    }

    private val keyguardManager: KeyguardManager by lazy {
        applicationContext.getSystemService(
            Context.KEYGUARD_SERVICE
        ) as KeyguardManager
    }


    private val encryptionService by lazy { EncryptionService() }

    private lateinit var textToEncrypt: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        if (isDeviceSecure()) {
            Toast.makeText(this, "Device is not secured", Toast.LENGTH_SHORT).show()
        }

        encryptData.setOnClickListener {
            textToEncrypt = dataToEncrypt.text.toString()
            encryptedData.text =
                encryptionService.encryptWithAndroidSymmetricKey(
                    KEY_ALIAS,
                    textToEncrypt
                )
        }

        decryptData.setOnClickListener {
            if (::textToEncrypt.isInitialized)
                decryptedData.text =
                    encryptionService.decryptWithAndroidSymmetricKey(
                        KEY_ALIAS,
                        encryptedData.text.toString()
                    )

        }
    }

    private fun isDeviceSecure(): Boolean =
        if (hasMarshmallow()) keyguardManager.isDeviceSecure else keyguardManager.isKeyguardSecure


    private fun hasMarshmallow() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M

}
