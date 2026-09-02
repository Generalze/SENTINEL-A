@rem
@rem Minimal Gradle wrapper launcher for Windows. See the long note at the top
@rem of `gradlew` for why this is a minimal launcher and not a copy of the
@rem official generated script, and for why gradle-wrapper.jar is not committed.
@rem
@echo off
setlocal

set DIRNAME=%~dp0
if "%DIRNAME%"=="" set DIRNAME=.
set WRAPPER_JAR=%DIRNAME%gradle\wrapper\gradle-wrapper.jar

if not exist "%WRAPPER_JAR%" (
    echo gradle-wrapper.jar is not present at "%WRAPPER_JAR%". 1>&2
    echo It is deliberately not committed. Run 'gradle wrapper' once in this 1>&2
    echo directory with Gradle 8.7 installed to generate it. 1>&2
    exit /b 1
)

set JAVACMD=java.exe
if defined JAVA_HOME if exist "%JAVA_HOME%\bin\java.exe" set JAVACMD=%JAVA_HOME%\bin\java.exe

"%JAVACMD%" -classpath "%WRAPPER_JAR%" org.gradle.wrapper.GradleWrapperMain %*
exit /b %ERRORLEVEL%
