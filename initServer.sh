#!/bin/bash

if [ "$(id -u)" != "0" ]; then
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
    else
        echo -e "${red}This script must be run as root or with sudo privileges.${no_color}"
        exit 1
    fi
else
    SUDO=""
fi

echo "初始化服务器配置..."

# 启动 ssh-agent
eval "$(ssh-agent -s)"

# 定义颜色代码
blue="\033[0;34m"
green="\033[0;32m"
yellow="\033[1;33m"
red="\033[0;31m"
no_color="\033[0m"

# 函数：初始化 SSH
function init_ssh() {
    local ssh_dir="$HOME/.ssh"
    local public_key_file="$ssh_dir/id_ed25519.pub"

    # 确保 .ssh 目录存在
    if [ ! -d "$ssh_dir" ]; then
        sudo mkdir -p "$ssh_dir"
        sudo chmod 700 "$ssh_dir"
    fi

    # 创建公钥文件，如果它不存在
    if [ ! -f "$public_key_file" ]; then
        sudo touch "$public_key_file"
    fi

    # 改变目录和文件的权限
    sudo chmod 700 "$ssh_dir"
    sudo chmod 600 "$ssh_dir"/*

    echo -e "${blue}初始化 SSH 已成功执行${no_color}"
}

# 函数：添加新用户
function add_user() {
    read -r -p "是否添加新用户? (y/n): " add_new_user
    if [[ $add_new_user == "y" ]]; then
        read -r -p "输入新用户名: " new_username
        ${SUDO} adduser "$new_username"
        read -r -p "是否赋予新用户 sudo 权限? (y/n): " grant_sudo
        if [[ $grant_sudo == "y" ]]; then
            ${SUDO} usermod -aG sudo "$new_username"
        fi
    fi
    echo -e "${blue}添加新用户 已成功执行${no_color}"
}

# 函数：显示系统内的所有用户并提供删除选项
function show_and_delete_user() {
    echo -e "${green}系统内的所有用户:${no_color}"
    local users
    # 仅列出具有有效登录 shell 的用户
    mapfile -t users < <(awk -F: '{ if ($7 ~ /^(\/bin\/bash|\/bin\/sh)$/) print $1 }' /etc/passwd)
    local choice
    for i in "${!users[@]}"; do
        echo "$((i+1)). ${users[i]}"
    done
    while true; do
        echo -ne "${yellow}选择要删除的用户编号 (或输入 'q' 退出): ${no_color}"
        read -r choice
        echo
        if [[ $choice =~ ^[0-9]+$ ]] && [ "$choice" -le "${#users[@]}" ]; then
            ${SUDO} deluser "${users[$((choice-1))]}"
            echo "已删除用户: ${users[$((choice-1))]}"
        elif [[ $choice == 'q' ]]; then
            break
        else
            echo -e "${red}无效输入，请重试。${no_color}"
        fi
    done
    echo -e "${blue}显示和删除用户 已成功执行${no_color}"
}


# 函数：检查 SSH 配置并进行修改
function check_ssh_config() {
    # 检查并修改 PermitRootLogin
    root_config_found=false
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
        read -p -r "${yellow}当前允许直接登录 ${no_color}${red}root${yellow} 账户。是否禁止? (y/n): ${no_color}" disable_root_login
        if [[ $disable_root_login == "y" ]]; then
            sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
            # echo "已禁止直接登录 root 账户。"
            root_config_found=true
        fi
    fi

    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        echo -e "${green}已禁止 直接 登录 ${no_color}${red}root${green} 账户。${no_color}"
        root_config_found=true
    fi

    if grep -q "^#*PermitRootLogin prohibit-password" /etc/ssh/sshd_config; then
        echo -e "${green}已禁止 使用密码 登录 ${no_color}${red}root${green} 账户。${no_color}"
        root_config_found=true
    fi

    if [ "$root_config_found" = false ]; then
    echo -e "${red}未检测到 root 配置，默认为 PermitRootLogin prohibit-password ${no_color}"
    fi

    # 检查并修改 PasswordAuthentication
    passwd_config_found=false
    if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
        read -p -r "${yellow}当前允许使用密码直接登录。是否禁止? (y/n): ${no_color}" disable_password_auth
        if [[ $disable_password_auth == "y" ]]; then
            sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
            # echo "已禁止使用密码直接登录。"
            passwd_config_found=true
        fi
    fi

    if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
        echo -e "${green}已禁止 使用密码 直接登录。${no_color}"
        passwd_config_found=true
    fi

    if [ "$passwd_config_found" = false ]; then
    echo -e "${red}未检测到 密码直接登录 配置，默认为 PasswordAuthentication yes ${no_color}"
    fi

    # 重启 SSH 服务以应用更改
    systemctl restart sshd
}

# 函数：检查 ssh-agent 托管的密钥
function check_ssh_agent_keys() {
    echo -e "${green}当前由 ssh-agent 托管的密钥:${no_color}"
    ssh-add -l
    echo -e "${blue}检查 ssh-agent 托管的密钥 已成功执行${no_color}"
}

# 函数：添加私钥到 ssh-agent
function add_key_to_ssh_agent() {
    echo -e "${green}Select a user to add their ${red}private${green} key to ssh-agent:${no_color}"
    local current_user_keys
    mapfile -t current_user_keys < <(find "$HOME/.ssh" -name "*id_ed25519*" -exec basename {} \;)
    if [ ${#current_user_keys[@]} -gt 0 ]; then
        echo -e "${yellow}SSH keys found in the current user's .ssh directory:${no_color}"
        for i in "${!current_user_keys[@]}"; do
            echo "$((i+1)). ${current_user_keys[i]}"
        done
        echo -ne "${yellow}Choose a key number, or 'q' to select a different user: ${no_color}"
        read -r key_choice
        echo
        if [[ $key_choice =~ ^[0-9]+$ ]] && [ "$key_choice" -le "${#current_user_keys[@]}" ]; then
            local selected_key="$HOME/.ssh/${current_user_keys[$((key_choice-1))]}"
            ssh-add "$selected_key"
            echo -e "${blue}Added ${red}private${blue} key to ssh-agent successfully${no_color}"
            return
        elif [[ $key_choice == 'q' ]]; then
            echo -e "${yellow}Selecting a different user...${no_color}"
        else
            echo -e "${red}Invalid input, please try again.${no_color}"
        fi
    else
        echo -e "${red}No SSH keys found in the current user's .ssh directory.${no_color}"
    fi

    local users
    mapfile -t users < <(awk -F: '{ if ($7 ~ /^(\/bin\/bash|\/bin\/sh)$/) print $1 }' /etc/passwd)
    for i in "${!users[@]}"; do
        echo "$((i+1)). ${users[i]}"
    done
    echo -ne "${yellow}Choose a user number (or 'q' to exit): ${no_color}"
    read -r user_choice
    echo
    if [[ $user_choice =~ ^[0-9]+$ ]] && [ "$user_choice" -le "${#users[@]}" ]; then
        local selected_user="${users[$((user_choice-1))]}"
        local user_ssh_keys
        mapfile -t user_ssh_keys < <(find "/home/$selected_user/.ssh" -name "*" -exec basename {} \;)
        if [ ${#user_ssh_keys[@]} -gt 0 ]; then
            echo -e "${yellow}Select a key from $selected_user's .ssh directory:${no_color}"
            for i in "${!user_ssh_keys[@]}"; do
                echo "$((i+1)). ${user_ssh_keys[i]}"
            done
            echo -ne "${yellow}Choose a key number: ${no_color}"
            read -r key_choice
            echo
            if [[ $key_choice =~ ^[0-9]+$ ]] && [ "$key_choice" -le "${#user_ssh_keys[@]}" ]; then
                local selected_key="/home/$selected_user/.ssh/${user_ssh_keys[$((key_choice-1))]}"
                ssh-add "$selected_key"
                echo -e "${blue}Added private key to ssh-agent successfully${no_color}"
                return
            else
                echo -e "${red}Invalid input, please try again.${no_color}"
            fi
        else
            echo -e "${red}No SSH keys found for $selected_user.${no_color}"
        fi
    elif [[ $user_choice == 'q' ]]; then
        return
    else
        echo -e "${red}Invalid input, please try again.${no_color}"
    fi
}

# 执行所有函数
init_ssh
add_user
show_and_delete_user
check_ssh_config
check_ssh_agent_keys
add_key_to_ssh_agent

echo
echo -e "${red}You should manually execute the following code to bind the ssh-agent:${no_color}"
echo
echo -e "${green}SSH_AGENT_PID=$SSH_AGENT_PID; export SSH_AGENT_PID;${no_color}"
echo -e "${green}SSH_AUTH_SOCK=$SSH_AUTH_SOCK; export SSH_AUTH_SOCK;${no_color}"
echo
echo -e "${blue}You can run ${no_color}${green}ssh-add -l${no_color}${blue} to check if ssh-agent is successfully bound${no_color}"
echo
echo -e "{blue}and use ${green}ssh -T git@github.com${blue} to test github connection!${no_color}"
echo
