// ==UserScript==
// @name         增强版一键Hook加密算法
// @version      2.0
// @description  增强版Hook脚本 - 支持更多加密算法、调用栈追踪、日志导出、性能监控
// @author       Enhanced Version
// @match        https://*/*
// @match        http://*/*
// @icon         data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==
// @grant        none
// ==/UserScript==

(function() {
    'use strict';
    
    // ==================== 配置面板 ====================
    window.CryptoHookConfig = {
        enabled: true,
        debugMode: false,
        showStack: true,
        logToConsole: true,
        maxLogs: 1000,
        colorOutput: true,
        exportEnabled: true
    };
    
    // ==================== 日志系统 ====================
    const CryptoLogger = {
        logs: [],
        colors: {
            AES: '#00bcd4',
            DES: '#ff9800',
            RSA: '#e91e63',
            MD5: '#4caf50',
            SHA: '#9c27b0',
            HMAC: '#ff5722',
            Base64: '#607d8b'
        },
        
        log(type, action, data) {
            const timestamp = new Date().toISOString();
            const stack = this.getCallStack();
            
            const logEntry = {
                timestamp,
                type,
                action,
                data,
                stack: window.CryptoHookConfig.showStack ? stack : null
            };
            
            this.logs.push(logEntry);
            if (this.logs.length > window.CryptoHookConfig.maxLogs) {
                this.logs.shift();
            }
            
            if (window.CryptoHookConfig.logToConsole) {
                this.prettyPrint(logEntry);
            }
            
            return logEntry;
        },
        
        getCallStack() {
            try {
                const stack = new Error().stack;
                const lines = stack.split('\n').slice(3, 8);
                return lines.map(line => line.trim()).join('\n');
            } catch(e) {
                return 'Stack trace unavailable';
            }
        },
        
        prettyPrint(entry) {
            const color = this.colors[entry.type] || '#333';
            const style = `color: ${color}; font-weight: bold; font-size: 12px;`;
            
            console.groupCollapsed(
                `%c[${entry.type}] ${entry.action} - ${entry.timestamp}`,
                style
            );
            
            Object.keys(entry.data).forEach(key => {
                console.log(`${key}:`, entry.data[key]);
            });
            
            if (entry.stack && window.CryptoHookConfig.showStack) {
                console.log('%cCall Stack:', 'color: #666; font-style: italic;');
                console.log(entry.stack);
            }
            
            console.groupEnd();
        },
        
        export() {
            const dataStr = JSON.stringify(this.logs, null, 2);
            const blob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `crypto_logs_${Date.now()}.json`;
            link.click();
            URL.revokeObjectURL(url);
            console.log(`✅ 已导出 ${this.logs.length} 条日志`);
        },
        
        clear() {
            this.logs = [];
            console.clear();
            console.log('✅ 日志已清空');
        },
        
        search(keyword) {
            return this.logs.filter(log => 
                JSON.stringify(log).toLowerCase().includes(keyword.toLowerCase())
            );
        }
    };
    
    // ==================== 工具函数 ====================
    function hex2b64(h) {
        const b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let i, c, ret = "";
        for (i = 0; i + 3 <= h.length; i += 3) {
            c = parseInt(h.substring(i, i + 3), 16);
            ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
        }
        if (i + 1 == h.length) {
            c = parseInt(h.substring(i, i + 1), 16);
            ret += b64map.charAt(c << 2);
        } else if (i + 2 == h.length) {
            c = parseInt(h.substring(i, i + 2), 16);
            ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
        }
        while ((ret.length & 3) > 0) ret += "=";
        return ret;
    }
    
    function safeStringify(obj) {
        try {
            if (typeof obj === 'string') return obj;
            if (obj && obj.toString && typeof obj.toString === 'function') {
                return obj.toString();
            }
            return String(obj);
        } catch(e) {
            return '[Object]';
        }
    }
    
    // ==================== 反调试绕过 ====================
    const constructorEx = constructor;
    Function.prototype.constructor = function(s) {
        if (s === "debugger") {
            console.warn('⚠️ 检测到debugger尝试，已拦截');
            return function() {};
        }
        return constructorEx(s);
    };
    
    // ==================== CryptoJS Hook ====================
    if (typeof CryptoJS !== 'undefined') {
        console.log('✅ 检测到CryptoJS库，开始Hook...');
        
        // AES加解密
        if (CryptoJS.AES) {
            const AESencrypt = CryptoJS.AES.encrypt;
            const AESdecrypt = CryptoJS.AES.decrypt;
            
            CryptoJS.AES.encrypt = function() {
                if (!window.CryptoHookConfig.enabled) {
                    return AESencrypt.apply(this, arguments);
                }
                
                try {
                    const data = safeStringify(arguments[0]);
                    const key = safeStringify(arguments[1]);
                    const iv = arguments[2]?.iv ? safeStringify(arguments[2].iv) : 'N/A';
                    const mode = arguments[2]?.mode?.toString() || 'CBC';
                    const padding = arguments[2]?.padding?.toString() || 'Pkcs7';
                    
                    CryptoLogger.log('AES', '加密', {
                        '明文': data,
                        '密钥': key,
                        '向量': iv,
                        '模式': mode,
                        '填充': padding
                    });
                    
                    if (window.CryptoHookConfig.debugMode) debugger;
                } catch(e) {
                    console.error('AES加密Hook错误:', e);
                }
                
                return AESencrypt.apply(this, arguments);
            };
            
            CryptoJS.AES.decrypt = function() {
                if (!window.CryptoHookConfig.enabled) {
                    return AESdecrypt.apply(this, arguments);
                }
                
                try {
                    const ciphertext = safeStringify(arguments[0]);
                    const key = safeStringify(arguments[1]);
                    const iv = arguments[2]?.iv ? safeStringify(arguments[2].iv) : 'N/A';
                    
                    CryptoLogger.log('AES', '解密', {
                        '密文': ciphertext,
                        '密钥': key,
                        '向量': iv
                    });
                    
                    if (window.CryptoHookConfig.debugMode) debugger;
                } catch(e) {
                    console.error('AES解密Hook错误:', e);
                }
                
                return AESdecrypt.apply(this, arguments);
            };
        }
        
        // DES/3DES
        ['DES', 'TripleDES'].forEach(algo => {
            if (CryptoJS[algo]) {
                const encrypt = CryptoJS[algo].encrypt;
                const decrypt = CryptoJS[algo].decrypt;
                
                CryptoJS[algo].encrypt = function() {
                    if (!window.CryptoHookConfig.enabled) {
                        return encrypt.apply(this, arguments);
                    }
                    
                    try {
                        CryptoLogger.log('DES', `${algo}加密`, {
                            '明文': safeStringify(arguments[0]),
                            '密钥': safeStringify(arguments[1]),
                            '向量': arguments[2]?.iv ? safeStringify(arguments[2].iv) : 'N/A'
                        });
                        
                        if (window.CryptoHookConfig.debugMode) debugger;
                    } catch(e) {
                        console.error(`${algo}加密Hook错误:`, e);
                    }
                    
                    return encrypt.apply(this, arguments);
                };
                
                CryptoJS[algo].decrypt = function() {
                    if (!window.CryptoHookConfig.enabled) {
                        return decrypt.apply(this, arguments);
                    }
                    
                    try {
                        CryptoLogger.log('DES', `${algo}解密`, {
                            '密文': safeStringify(arguments[0]),
                            '密钥': safeStringify(arguments[1])
                        });
                        
                        if (window.CryptoHookConfig.debugMode) debugger;
                    } catch(e) {
                        console.error(`${algo}解密Hook错误:`, e);
                    }
                    
                    return decrypt.apply(this, arguments);
                };
            }
        });
        
        // HMAC系列
        ['HmacMD5', 'HmacSHA1', 'HmacSHA256', 'HmacSHA384', 'HmacSHA512'].forEach(algo => {
            if (CryptoJS[algo]) {
                const original = CryptoJS[algo];
                CryptoJS[algo] = function() {
                    if (!window.CryptoHookConfig.enabled) {
                        return original.apply(this, arguments);
                    }
                    
                    try {
                        CryptoLogger.log('HMAC', algo, {
                            '数据': safeStringify(arguments[0]),
                            '密钥': safeStringify(arguments[1])
                        });
                        
                        if (window.CryptoHookConfig.debugMode) debugger;
                    } catch(e) {
                        console.error(`${algo} Hook错误:`, e);
                    }
                    
                    return original.apply(this, arguments);
                };
            }
        });
        
        // SHA系列
        ['MD5', 'SHA1', 'SHA3', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'RIPEMD160'].forEach(algo => {
            if (CryptoJS[algo]) {
                const original = CryptoJS[algo];
                CryptoJS[algo] = function() {
                    if (!window.CryptoHookConfig.enabled) {
                        return original.apply(this, arguments);
                    }
                    
                    try {
                        CryptoLogger.log('SHA', algo, {
                            '数据': safeStringify(arguments[0])
                        });
                        
                        if (window.CryptoHookConfig.debugMode) debugger;
                    } catch(e) {
                        console.error(`${algo} Hook错误:`, e);
                    }
                    
                    return original.apply(this, arguments);
                };
            }
        });
        
        // Rabbit加解密
        if (CryptoJS.Rabbit) {
            const RabbitEncrypt = CryptoJS.Rabbit.encrypt;
            const RabbitDecrypt = CryptoJS.Rabbit.decrypt;
            
            CryptoJS.Rabbit.encrypt = function() {
                if (!window.CryptoHookConfig.enabled) {
                    return RabbitEncrypt.apply(this, arguments);
                }
                
                try {
                    CryptoLogger.log('AES', 'Rabbit加密', {
                        '明文': safeStringify(arguments[0]),
                        '密钥': safeStringify(arguments[1])
                    });
                    
                    if (window.CryptoHookConfig.debugMode) debugger;
                } catch(e) {
                    console.error('Rabbit加密Hook错误:', e);
                }
                
                return RabbitEncrypt.apply(this, arguments);
            };
            
            CryptoJS.Rabbit.decrypt = function() {
                if (!window.CryptoHookConfig.enabled) {
                    return RabbitDecrypt.apply(this, arguments);
                }
                
                try {
                    CryptoLogger.log('AES', 'Rabbit解密', {
                        '密文': safeStringify(arguments[0]),
                        '密钥': safeStringify(arguments[1])
                    });
                    
                    if (window.CryptoHookConfig.debugMode) debugger;
                } catch(e) {
                    console.error('Rabbit解密Hook错误:', e);
                }
                
                return RabbitDecrypt.apply(this, arguments);
            };
        }
        
        // PBKDF2
        if (CryptoJS.PBKDF2) {
            const PBKDF2Original = CryptoJS.PBKDF2;
            CryptoJS.PBKDF2 = function() {
                if (!window.CryptoHookConfig.enabled) {
                    return PBKDF2Original.apply(this, arguments);
                }
                
                try {
                    CryptoLogger.log('SHA', 'PBKDF2', {
                        '密码': safeStringify(arguments[0]),
                        '盐值': safeStringify(arguments[1]),
                        '密钥长度': arguments[2]?.keySize || 'N/A',
                        '迭代次数': arguments[2]?.iterations || 'N/A'
                    });
                    
                    if (window.CryptoHookConfig.debugMode) debugger;
                } catch(e) {
                    console.error('PBKDF2 Hook错误:', e);
                }
                
                return PBKDF2Original.apply(this, arguments);
            };
        }
        
        // EvpKDF
        if (CryptoJS.EvpKDF) {
            const EvpKDFOriginal = CryptoJS.EvpKDF;
            CryptoJS.EvpKDF = function() {
                if (!window.CryptoHookConfig.enabled) {
                    return EvpKDFOriginal.apply(this, arguments);
                }
                
                try {
                    CryptoLogger.log('SHA', 'EvpKDF', {
                        '密码': safeStringify(arguments[0]),
                        '盐值': safeStringify(arguments[1]),
                        '密钥长度': arguments[2]?.keySize || 'N/A',
                        '迭代次数': arguments[2]?.iterations || 'N/A'
                    });
                    
                    if (window.CryptoHookConfig.debugMode) debugger;
                } catch(e) {
                    console.error('EvpKDF Hook错误:', e);
                }
                
                return EvpKDFOriginal.apply(this, arguments);
            };
        }
    }
    
    // ==================== JSEncrypt Hook ====================
    if (typeof JSEncrypt !== 'undefined') {
        console.log('✅ 检测到JSEncrypt库，开始Hook...');
        
        const RSA = JSEncrypt.prototype;
        
        if (RSA.encrypt) {
            const RSAEncrypt = RSA.encrypt;
            RSA.encrypt = function() {
                if (!window.CryptoHookConfig.enabled) {
                    return RSAEncrypt.apply(this, arguments);
                }
                
                try {
                    CryptoLogger.log('RSA', 'JSEncrypt加密', {
                        '明文': safeStringify(arguments[0]),
                        '公钥': this.key ? '已设置' : '未设置'
                    });
                    
                    if (window.CryptoHookConfig.debugMode) debugger;
                } catch(e) {
                    console.error('RSA加密Hook错误:', e);
                }
                
                return RSAEncrypt.apply(this, arguments);
            };
        }
        
        if (RSA.decrypt) {
            const RSADecrypt = RSA.decrypt;
            RSA.decrypt = function() {
                if (!window.CryptoHookConfig.enabled) {
                    return RSADecrypt.apply(this, arguments);
                }
                
                try {
                    CryptoLogger.log('RSA', 'JSEncrypt解密', {
                        '密文': safeStringify(arguments[0]),
                        '私钥': this.key ? '已设置' : '未设置'
                    });
                    
                    if (window.CryptoHookConfig.debugMode) debugger;
                } catch(e) {
                    console.error('RSA解密Hook错误:', e);
                }
                
                return RSADecrypt.apply(this, arguments);
            };
        }
        
        if (RSA.setPublicKey) {
            const SetPublic = RSA.setPublicKey;
            RSA.setPublicKey = function() {
                if (!window.CryptoHookConfig.enabled) {
                    return SetPublic.apply(this, arguments);
                }
                
                try {
                    CryptoLogger.log('RSA', '设置公钥', {
                        '公钥': safeStringify(arguments[0])
                    });
                    
                    if (window.CryptoHookConfig.debugMode) debugger;
                } catch(e) {
                    console.error('设置公钥Hook错误:', e);
                }
                
                return SetPublic.apply(this, arguments);
            };
        }
        
        if (RSA.setPrivateKey) {
            const SetPrivate = RSA.setPrivateKey;
            RSA.setPrivateKey = function() {
                if (!window.CryptoHookConfig.enabled) {
                    return SetPrivate.apply(this, arguments);
                }
                
                try {
                    CryptoLogger.log('RSA', '设置私钥', {
                        '私钥': safeStringify(arguments[0])
                    });
                    
                    if (window.CryptoHookConfig.debugMode) debugger;
                } catch(e) {
                    console.error('设置私钥Hook错误:', e);
                }
                
                return SetPrivate.apply(this, arguments);
            };
        }
    }
    
    // ==================== Base64 Hook ====================
    if (typeof atob !== 'undefined') {
        const atobOriginal = window.atob;
        window.atob = function() {
            if (!window.CryptoHookConfig.enabled) {
                return atobOriginal.apply(this, arguments);
            }
            
            try {
                CryptoLogger.log('Base64', 'Base64解码', {
                    '编码数据': safeStringify(arguments[0])
                });
            } catch(e) {
                console.error('Base64解码Hook错误:', e);
            }
            
            return atobOriginal.apply(this, arguments);
        };
    }
    
    if (typeof btoa !== 'undefined') {
        const btoaOriginal = window.btoa;
        window.btoa = function() {
            if (!window.CryptoHookConfig.enabled) {
                return btoaOriginal.apply(this, arguments);
            }
            
            try {
                CryptoLogger.log('Base64', 'Base64编码', {
                    '原始数据': safeStringify(arguments[0])
                });
            } catch(e) {
                console.error('Base64编码Hook错误:', e);
            }
            
            return btoaOriginal.apply(this, arguments);
        };
    }
    
    // ==================== 控制台API ====================
    window.CryptoHook = {
        enable: () => {
            window.CryptoHookConfig.enabled = true;
            console.log('✅ Hook已启用');
        },
        disable: () => {
            window.CryptoHookConfig.enabled = false;
            console.log('⛔ Hook已禁用');
        },
        debug: (enable = true) => {
            window.CryptoHookConfig.debugMode = enable;
            console.log(`${enable ? '✅' : '⛔'} 调试模式${enable ? '已启用' : '已禁用'}`);
        },
        showStack: (show = true) => {
            window.CryptoHookConfig.showStack = show;
            console.log(`${show ? '✅' : '⛔'} 调用栈显示${show ? '已启用' : '已禁用'}`);
        },
        export: () => CryptoLogger.export(),
        clear: () => CryptoLogger.clear(),
        search: (keyword) => {
            const results = CryptoLogger.search(keyword);
            console.log(`🔍 找到 ${results.length} 条匹配记录:`, results);
            return results;
        },
        stats: () => {
            const stats = {};
            CryptoLogger.logs.forEach(log => {
                const key = `${log.type}-${log.action}`;
                stats[key] = (stats[key] || 0) + 1;
            });
            console.table(stats);
            return stats;
        },
        help: () => {
            console.log(`
🔧 CryptoHook 增强版使用说明:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CryptoHook.enable()          - 启用Hook
CryptoHook.disable()         - 禁用Hook
CryptoHook.debug(true/false) - 启用/禁用调试断点
CryptoHook.showStack(true/false) - 显示/隐藏调用栈
CryptoHook.export()          - 导出日志到JSON文件
CryptoHook.clear()           - 清空日志
CryptoHook.search('keyword') - 搜索日志
CryptoHook.stats()           - 查看统计信息
CryptoHook.help()            - 显示帮助信息
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            `);
        }
    };
    
    // ==================== 初始化完成 ====================
    console.log(`
%c🎉 加密算法Hook脚本 v2.0 已加载 
%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
输入 CryptoHook.help() 查看使用说明
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
        'color: #4CAF50; font-size: 16px; font-weight: bold;',
        'color: #666; font-size: 12px;'
    );
    
})();