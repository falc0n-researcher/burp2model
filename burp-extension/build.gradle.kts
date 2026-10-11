plugins {
    java
}

group = "burp2model"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.5")
}

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(17))
}

tasks.jar {
    archiveBaseName.set("burp2model")
    // a plain jar: the extension only uses the JDK and the API Burp provides
    from(sourceSets.main.get().output)
}
