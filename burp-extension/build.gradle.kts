plugins {
    java
}

group = "burp2model"
version = "1.1.0"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.5")

    // tests only: the jar itself stays dependency-free
    testImplementation("net.portswigger.burp.extensions:montoya-api:2025.5")
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(17))
}

tasks.jar {
    archiveBaseName.set("burp2model")
    // everything is in the jar: the engine is plain Java and needs nothing but Burp
    from(sourceSets.main.get().output)
}

tasks.test {
    useJUnitPlatform()
    systemProperty("java.awt.headless", "true")
    // the bundled exports live in the repository's samples folder
    systemProperty("burp2model.samples", rootDir.resolve("../samples").absolutePath)
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
