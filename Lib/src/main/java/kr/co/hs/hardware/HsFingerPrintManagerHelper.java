package kr.co.hs.hardware;

import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


@RequiresApi(api = Build.VERSION_CODES.M)
public class HsFingerPrintManagerHelper extends FingerprintManager.AuthenticationCallback{
    private Context mContext;
    private final FingerprintManager mFingerprintManager;
    private CancellationSignal mCancellationSignal;
    private boolean mSelfCancelled;

    private OnAuthenticationErrorListener mOnAuthenticationErrorListener;
    private OnAuthenticationFailedListener mOnAuthenticationFailedListener;
    private OnAuthenticationHelpListener mOnAuthenticationHelpListener;
    private OnAuthenticationSucceededListener mOnAuthenticationSucceededListener;


    public HsFingerPrintManagerHelper(Context context) {
        this.mContext = context;
        mFingerprintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
    }

    public boolean isFingerprintAuthAvailable() {
        // The line below prevents the false positive inspection from Android Studio
        // noinspection ResourceType
        return mFingerprintManager.isHardwareDetected()
                && mFingerprintManager.hasEnrolledFingerprints();
    }


    public boolean startListening() {
        if (!isFingerprintAuthAvailable()) {
            return false;
        }

        try {
            Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES+"/"+KeyProperties.BLOCK_MODE_CBC+"/"+KeyProperties.ENCRYPTION_PADDING_PKCS7);

            try{
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
                keyStore.load(null);
                keyGenerator.init(new KeyGenParameterSpec.Builder(mContext.getPackageName(), KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_CBC).setUserAuthenticationRequired(true).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7).build());
                keyGenerator.generateKey();
                keyStore.load(null);
                SecretKey key = (SecretKey) keyStore.getKey(mContext.getPackageName(), null);
                cipher.init(Cipher.ENCRYPT_MODE, key);
            }catch (Exception e){
                e.printStackTrace();
            }


            FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
            mCancellationSignal = new CancellationSignal();
            mSelfCancelled = false;
            // The line below prevents the false positive inspection from Android Studio
            // noinspection ResourceType
            mFingerprintManager
                    .authenticate(cryptoObject, mCancellationSignal, 0 /* flags */, this, null);

            return true;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }

        return false;
    }

    public void stopListening() {
        if (mCancellationSignal != null) {
            mSelfCancelled = true;
            mCancellationSignal.cancel();
            mCancellationSignal = null;
        }
    }


    public void setOnAuthenticationErrorListener(OnAuthenticationErrorListener onAuthenticationErrorListener) {
        mOnAuthenticationErrorListener = onAuthenticationErrorListener;
    }

    public void setOnAuthenticationFailedListener(OnAuthenticationFailedListener onAuthenticationFailedListener) {
        mOnAuthenticationFailedListener = onAuthenticationFailedListener;
    }

    public void setOnAuthenticationHelpListener(OnAuthenticationHelpListener onAuthenticationHelpListener) {
        mOnAuthenticationHelpListener = onAuthenticationHelpListener;
    }

    public void setOnAuthenticationSucceededListener(OnAuthenticationSucceededListener onAuthenticationSucceededListener) {
        mOnAuthenticationSucceededListener = onAuthenticationSucceededListener;
    }

    public interface OnAuthenticationErrorListener{
        void onAuthenticationError(int errorCode, CharSequence errString);
    }
    public interface OnAuthenticationHelpListener{
        void onAuthenticationHelp(int helpCode, CharSequence helpString);
    }
    public interface OnAuthenticationSucceededListener{
        void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result);
    }
    public interface OnAuthenticationFailedListener{
        void onAuthenticationFailed();
    }


    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);
        if(this.mOnAuthenticationErrorListener != null)
            this.mOnAuthenticationErrorListener.onAuthenticationError(errorCode, errString);
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        super.onAuthenticationHelp(helpCode, helpString);
        if(this.mOnAuthenticationHelpListener != null)
            this.mOnAuthenticationHelpListener.onAuthenticationHelp(helpCode, helpString);
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        if(this.mOnAuthenticationSucceededListener != null)
            this.mOnAuthenticationSucceededListener.onAuthenticationSucceeded(result);
    }

    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
        if(this.mOnAuthenticationFailedListener != null)
            this.mOnAuthenticationFailedListener.onAuthenticationFailed();
    }
}
