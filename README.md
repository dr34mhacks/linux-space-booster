<div align="center">

# 🚀 Linux Space Booster

![Linux Space Booster](https://img.shields.io/badge/Linux%20Space%20Booster-v1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platforms](https://img.shields.io/badge/platforms-Kali%20|%20Ubuntu%20|%20Debian%20|%20Mint-purple)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Disk Space Freed](https://img.shields.io/badge/freed-2.9GB%20and%20counting-orange)

**Advanced Disk Space Management Utility for Linux Virtual Machines**

**Linux Space Booster** is an advanced, secure disk space cleanup utility specifically designed for Linux virtual machines. It intelligently cleans caches, logs, and temporary files to reclaim valuable disk space without risking system stability or user data.

With built-in safety checks and distribution-specific optimizations, Linux Space Booster is the perfect solution for maintaining lean, efficient VMs for development, penetration testing, and general use.

</div>

## ✨ Key Features

- **🛡️ Safe By Design**: Critical system paths protected with multiple safety checks
- **🧠 Intelligent Cleaning**: Distribution-specific optimizations for maximum effectiveness
- **🔍 Comprehensive Analysis**: Visual disk usage summary with cleanup recommendations
- **🧹 Targeted Cleanup**: Multiple cleanup modes from basic to advanced
- **📊 Detailed Reporting**: Complete cleanup reports with space freed metrics
- **⚙️ Cross-Distribution Support**: Works on Kali, Parrot, Ubuntu, Mint, and Debian-based systems
- **🔄 Interactive Interface**: User-friendly menu with interactive confirmations

## 🔧 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/dr34mhacks/linux-space-booster.git

# Navigate to the directory
cd linux-space-booster

# Make the script executable
chmod +x linux_space_booster.sh

# Run the script
sudo ./linux_space_booster.sh
```

### Optional: Make it available system-wide

```bash
sudo cp linux_space_booster.sh /usr/local/bin/linux-space-booster
sudo chmod +x /usr/local/bin/linux-space-booster
```

## 📺 Screenshot

<div align="center">
<img width="1277" alt="linux space booster" src="https://github.com/user-attachments/assets/4d29b2c4-b207-4027-8768-479eaed97eeb" />
</div>

## 🚀 Usage

### Interactive Mode (Recommended)

Simply run the script without arguments to access the interactive menu:

```bash
sudo ./linux-space-booster
```


### Command Line Options

| Option | Description |
|--------|-------------|
| `--quick` | Quick safe cleanup (no confirmations) |
| `--advanced` | Advanced cleanup with confirmations |
| `--user-only` | Clean only user cache files (no root required) |
| `--dry-run` | Preview what would be cleaned without making changes |
| `--force` | Skip all confirmations (use with caution) |
| `--help` | Display help information |

### Examples

```bash
# Quick cleanup
sudo linux-space-booster --quick

# Advanced cleanup
sudo linux-space-booster --advanced

# User-only cleanup (no root required)
linux-space-booster --user-only

# Dry run (preview only)
sudo linux-space-booster --dry-run
```

## 🧹 What Gets Cleaned

| Category | What's Cleaned | What's Preserved |
|----------|----------------|------------------|
| **APT Cache** | Package files (.deb), orphaned packages | Package lists, repository data |
| **System Logs** | Old log files (30+ days), rotated logs | Current active logs |
| **Temporary Files** | Files in /tmp older than 7 days | Recent temp files, active temp files |
| **User Caches** | Browser caches, thumbnail caches | User data, configurations |
| **PostgreSQL** | Old log files (30+ days) | Database data, current logs, configuration |
| **Metasploit** | Old log files (30+ days) | Scan data, loot, exploits, configuration |
| **Wireshark** | Temporary files (.tmp) | Capture files (.pcap), configuration |
| **Journal** | Old journal entries | Recent journal entries |
| **Snap** | Old package versions | Current snap packages, configurations |
| **Kernels** | Old unused kernels | Current kernel, recent kernels |

## 🛡️ Safety Features

Linux Space Booster includes multiple layers of protection to ensure your system remains stable and your data safe:

- **Critical Path Protection**: System directories are explicitly protected
- **Active File Detection**: Files in use by running processes are never deleted
- **User Data Preservation**: Personal files and settings are never touched
- **Evidence Protection**: Forensic data and capture files are preserved
- **Configuration Safety**: System and tool configurations are protected
- **Kernel Safety**: Current and recent kernels are always preserved

## 💻 Supported Distributions

- **Kali Linux**: Specialized cleaning for penetration testing tools
- **Parrot OS**: Optimized for security tools and configurations
- **Ubuntu**: Enhanced cleaning for desktop environments
- **Linux Mint**: Tailored for Mint-specific packages and caches
- **Debian**: Core system optimization for Debian-based distributions

## 📊 Performance

Average disk space reclaimed on first run:

| Distribution | Average Space Freed |
|--------------|---------------------|
| Kali Linux | 1.2 - 2.5 GB |
| Ubuntu | 0.8 - 1.5 GB |
| Linux Mint | 0.9 - 1.7 GB |
| Debian | 0.5 - 1.0 GB |

## 🔄 Regular Maintenance Recommendation

For optimal system performance, we recommend running Linux Space Booster:
- **Basic Cleanup**: Weekly
- **Advanced Cleanup**: Monthly
- **Kernel Cleanup**: After system updates that install new kernels

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Sid Joshi** - [@dr34mhacks](https://github.com/dr34mhacks)

## 🙏 Acknowledgments

- Inspired by various disk cleaning utilities across Linux distributions
- Thanks to all the testers who provided valuable feedback

---

<div align="center">
  <p>⭐ If you find this tool useful, please consider giving it a star! ⭐</p>
  <p>📧 For issues, suggestions, or contributions, please open an issue on GitHub.</p>
  
  <sub>Made with ❤️ for the Linux community</sub>
</div>
