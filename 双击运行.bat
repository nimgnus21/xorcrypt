@echo off
chcp 65001 >nul
rem 双击本文件即可打开菜单，无需手动输入命令。
rem 自动选择 py 或 python 启动 xorcrypt.py。
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py xorcrypt.py
) else (
    python xorcrypt.py
)
echo.
pause
