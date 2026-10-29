# Guía de Seguridad en Enlaces Profundos Móviles (Deep Links) y Esquemas URI

Esta referencia técnica describe los principios de análisis arquitectónico, modelado de fronteras de confianza y bastionado para vulnerabilidades en **Deep Links y Esquemas URI Personalizados**, catalogada bajo **`VULN-ARCH-031`** en **Devia-CyberSecurity**.

---

## 🏛️ Contexto y Mecanismo del Fallo

Las aplicaciones móviles (Android, iOS) y de escritorio registran esquemas de URI personalizados (e.g. `myapp://`, `slack://`, `zoom://`) o enlaces basados en HTTP/HTTPS para permitir navegación directa hacia vistas o acciones específicas dentro de la aplicación.

Existen dos tipos principales de enlaces profundos:
1. **Custom URI Schemes (`myapp://path?param=value`):**
   - No tienen autoridad central ni verificación de propiedad. Cualquier aplicación maliciosa instalada en el mismo dispositivo puede registrar el mismo esquema URI en su manifiesto.
   - Si el sistema operativo muestra un selector de aplicaciones o deriva la ejecución a la aplicación atacante, se puede interceptar el flujo de datos.
   - Si la aplicación legítima procesa parámetros no sanitizados recibidos en la URI (e.g. `myapp://open_url?target=...`), puede ser inducida a realizar llamadas arbitrarias, abrir webviews vulnerables a XSS móvil o ejecutar acciones sin autorización.
2. **Universal Links (iOS) y Android App Links (Android):**
   - Utilizan URLs HTTPS estándar asociadas a un dominio web propiedad del desarrollador mediante archivos de verificación criptográfica (`/.well-known/assetlinks.json` en Android y `/.well-known/apple-app-site-association` en iOS).
   - Solo la aplicación autorizada por el archivo de asociación del dominio puede capturar los enlaces de forma automática y exclusiva.

---

## 🔍 Taxonomía y Mapeo Multimarco

| Estándar / Marco | Identificador | Denominación Oficial |
| :--- | :--- | :--- |
| **CWE** | **CWE-939** | Improper Authorization in Handler for Custom URL Scheme |
| **CWE** | **CWE-20** | Improper Input Validation |
| **OWASP Mobile** | **M01:2024** | Improper Credential Usage / Insecure Inter-Process Communication |
| **OWASP Top 10** | **A01:2021/2025** | Broken Access Control |
| **MITRE ATT&CK** | **T1204** | User Execution: Malicious Link |
| **Devia Catalog** | **`VULN-ARCH-031`** | Mobile & Desktop Deep Link Custom Scheme Hijacking & Parameter Injection |

---

## 💻 Configuración Vulnerable vs Hardened

### Antipatrón Vulnerable en Android (AndroidManifest.xml)
```xml
<!-- VULNERABLE: Esquema URI personalizado sin verificación de dominio -->
<activity android:name=".DeepLinkActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <!-- Peligro: Cualquier app puede reclamar 'myapp' -->
        <data android:scheme="myapp" android:host="authorize" />
    </intent-filter>
</activity>
```

### Procesamiento Inseguro de Parámetros en Java / Kotlin
```kotlin
// VULNERABLE: Confianza ciega en parámetros de la URI
class DeepLinkActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val data: Uri? = intent.data
        val targetUrl = data?.getQueryParameter("redirect_url")
        
        // Peligro: Redirección abierta o carga de WebView sin validar origen!
        webView.loadUrl(targetUrl ?: "https://example.com")
    }
}
```

### Configuración Hardened: Android App Links con `autoVerify="true"`
```xml
<!-- SEGURO: Verificación obligatoria de dominio mediante App Links -->
<activity android:name=".DeepLinkActivity" android:exported="true">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        
        <data android:scheme="https"
              android:host="app.example.com"
              android:pathPrefix="/deep/" />
    </intent-filter>
</activity>
```

### Verificación Criptográfica en Servidor (`/.well-known/assetlinks.json`)
```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.myapp",
    "sha256_cert_fingerprints": [
      "14:6D:E9:01:07:52:07:71:02:E2:B6:22:CD:85:AA:F6:4A:21:BC:07:73:CD:E5:60:BA:84:48:20:FF:2C:9E:EB"
    ]
  }
}]
```

### Procesamiento Seguro de Parámetros en el Cliente
```kotlin
// SEGURO: Validación de lista blanca y rechazo de esquemas no confiables
val allowedHosts = setOf("app.example.com", "api.example.com")

val data: Uri? = intent.data
data?.let { uri ->
    val host = uri.host?.lowercase()
    if (host != null && allowedHosts.contains(host)) {
        // Procesar exclusivamente rutas autorizadas
        val action = uri.path
        when (action) {
            "/deep/profile" -> showProfile()
            "/deep/settings" -> showSettings()
            else -> navigateToHome()
        }
    } else {
        Log.w("DeepLink", "Invalid or unauthorized deep link host: $host")
        finish()
    }
}
```

---

## 🚫 Antipatrón Crítico: Transmisión de Tokens de Autenticación en URIs

> [!CAUTION]
> **Queda estrictamente prohibido pasar códigos de autorización OAuth o tokens de acceso a través de esquemas URI personalizados (`myapp://callback?code=...`):**
> Otras aplicaciones en el dispositivo pueden escuchar el intent o monitorear el registro de enlaces para robar el token. Debe utilizarse **OAuth 2.1 con PKCE estricto** y Universal Links/App Links con verificación de dominio.

---

## ✅ Checklist de Auditoría para Evaluadores de Devia-CyberSecurity

- [ ] Todas las actividades receptoras de enlaces externos (`android:exported="true"`) validan rigurosamente el origen y esquema del intent.
- [ ] Se utilizan **Android App Links** (`autoVerify="true"`) y **Apple Universal Links** en lugar de esquemas URI personalizados abiertos.
- [ ] El archivo de verificación (`assetlinks.json` o `apple-app-site-association`) está servido sobre HTTPS estricto con `Content-Type: application/json` y sin redirecciones.
- [ ] Ninguna URL recibida por un deep link se pasa directamente a un `WebView.loadUrl()` sin validación contra lista blanca de dominios.
- [ ] No se transmiten credenciales, tokens de restablecimiento de contraseña ni códigos OAuth en fragmentos o query parameters de enlaces profundos.
