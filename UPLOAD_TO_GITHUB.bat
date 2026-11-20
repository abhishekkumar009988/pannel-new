@echo off
setlocal EnableExtensions
title STAR INVESTIGATOR - Upload Complete Folders To GitHub
cd /d "%~dp0"

echo.
echo ========================================================
echo   STAR INVESTIGATOR - GITHUB COMPLETE FOLDER UPLOADER
echo ========================================================
echo.
echo Target: https://github.com/abhishekkumar009988/pannel
echo Branch: main
echo Folders: templates, static, owner_services
echo.
echo IMPORTANT: This repository was PUBLIC when checked.
echo Make it PRIVATE in GitHub Settings before uploading.
echo Never upload data, .env, or private keys.
echo.
choice /C YN /M "Continue with safe project source upload"
if errorlevel 2 goto :cancel

if not exist "%~dp0templates\login.html" goto :not_extracted
if not exist "%~dp0static\style.css" goto :not_extracted
if not exist "%~dp0owner_services\licensing_db.py" goto :not_extracted

where git >nul 2>&1
if errorlevel 1 goto :no_git

set "CLONE_DIR=%TEMP%\starinvestigator_github_%RANDOM%_%RANDOM%"
echo.
echo [1/4] Downloading existing GitHub repository...
git clone --quiet --single-branch --branch main "https://github.com/abhishekkumar009988/pannel.git" "%CLONE_DIR%"
if errorlevel 1 goto :clone_failed

echo [2/4] Copying complete folders and code...
for %%D in (templates static owner_services) do (
    xcopy "%~dp0%%D\*" "%CLONE_DIR%\%%D\" /E /I /Y /Q >nul
    if errorlevel 2 goto :copy_failed
)

for %%F in (.env.example .gitignore Procfile README.md owner_app.py requirements.txt run_owner_dashboard.bat test_owner_init.py) do (
    if not exist "%~dp0%%F" goto :copy_failed
    copy /Y "%~dp0%%F" "%CLONE_DIR%\%%F" >nul
    if errorlevel 1 goto :copy_failed
)

cd /d "%CLONE_DIR%"
echo [3/4] Committing files without secrets or customer database...
git add -- .env.example .gitignore Procfile README.md owner_app.py requirements.txt run_owner_dashboard.bat test_owner_init.py templates static owner_services
if errorlevel 1 goto :git_failed

git diff --cached --quiet
if not errorlevel 1 goto :already_synced

git -c user.name="abhishekkumar009988" -c user.email="263536287+abhishekkumar009988@users.noreply.github.com" commit -m "Upload complete Star Investigator owner panel folders"
if errorlevel 1 goto :git_failed

echo [4/4] Pushing to GitHub (a browser login may appear)...
git push origin main
if errorlevel 1 goto :push_failed

echo.
echo SUCCESS: Your complete folder structure is now on GitHub.
start "" "https://github.com/abhishekkumar009988/pannel"
goto :end

:already_synced
echo.
echo Already synced: No changes need to be uploaded.
start "" "https://github.com/abhishekkumar009988/pannel"
goto :end

:not_extracted
echo ERROR: ZIP was not fully extracted.
echo Right-click the ZIP, choose Extract All, then double-click UPLOAD_TO_GITHUB.bat.
goto :end

:no_git
echo ERROR: Git is not installed on this Windows PC.
echo Install Git for Windows from the official website below, reopen this BAT, and try again.
start "" "https://git-scm.com/downloads/win"
goto :end

:clone_failed
echo ERROR: Could not download the GitHub repository. Check network and GitHub login.
goto :end

:copy_failed
echo ERROR: Folder or file copying failed. Keep all extracted files in one folder.
goto :end

:git_failed
echo ERROR: Git could not stage or commit the project. Share this window's error message.
goto :end

:push_failed
echo ERROR: GitHub rejected the push. Sign into your GitHub account if asked.
echo The working clone was kept at: %CLONE_DIR%
echo If you have no repository write access, GitHub will block the upload.
goto :end

:cancel
echo Upload cancelled. No GitHub files were modified.

:end
echo.
pause
endlocal
