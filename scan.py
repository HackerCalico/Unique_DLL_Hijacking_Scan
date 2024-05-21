import re
import os
import sys

def GetPayload(path, exeName):
    hijackableDLLs = {}
    exeFullPath = path + '/' + exeName
    exeSize = os.path.getsize(exeFullPath)
    if exeSize > 10 * 1024 * 1024: # 10MB
        return
    # 获取导入表
    imports = os.popen('dumpbin /imports "' + exeFullPath + '"').read()
    # 匹配 DLL 信息
    dllsInfo = re.findall(r'([\S]+\.[dlDL]{3})[\s\S]+?\n\n([\s\S]+?\n)\n', imports)
    for dllInfo in dllsInfo:
        dllName = dllInfo[0]
        if '?' not in dllInfo[1] and dllName.lower() not in MicrosoftDlls:
            functionNames = re.findall(r'[0-9A-F][\s]([\S]+)\n', dllInfo[1])
            hijackableDLLs[dllName] = functionNames # {'xxx.dll': ['func1', 'func2', ...], ...}
    # 获取 EXE 信息
    if hijackableDLLs:
        print(exeFullPath)
        # 文件大小
        if exeSize > 1024 * 1024:
            exeSize = str(round(exeSize/(1024 * 1024), 2)) + 'MB'
        elif exeSize > 1024:
            exeSize = str(round(exeSize/1024, 2)) + 'KB'
        else:
            exeSize = str(round(exeSize, 2)) + 'B'
        # 位数
        sigcheck = os.popen('sigcheck64 -accepteula "' + exeFullPath + '"').read()
        if '64-bit' in sigcheck:
            bit = 'x64'
        elif '32-bit' in sigcheck:
            bit = 'x86'
        # 数字签名
        if re.search(r'Publisher:[\s]+n/a', sigcheck):
            publisher = ' '
            payload = [bit + ' ' + exeSize + ' 无数字签名 ' + exeName]
        else:
            publisher = '数字签名 '
            payload = [bit + ' ' + exeSize + ' 有数字签名 ' + exeName]
        # 生成导出函数
        for dllName, functionNames in hijackableDLLs.items():
            payload += ['\n' + dllName]
            for functionName in functionNames:
                payload += ['extern "C" __declspec(dllexport) int ' + functionName + '() { return 0; }']
        # 写入文件
        fileName = bit + ' ' + exeSize + ' ' + publisher + exeName
        try:
            os.mkdir('Payload')
        except:
            pass
        try:
            os.mkdir('Payload/' + fileName)
        except:
            pass
        with open('Payload/' + fileName + '/' + fileName + '.txt', 'w') as f:
            f.write('\n'.join(payload))
        os.popen('copy "' + exeFullPath.replace('/', '\\') + '" "' + os.getcwd() + '/Payload/' + fileName + '"')
        
# 收集微软 DLL
def Scan(path, suffix):
    try:
        for fileName in os.listdir(path):
            if os.path.isdir(path + '/' + fileName): # 文件夹
                Scan(path + '/' + fileName, suffix)
            elif fileName[-4:] == suffix:
                if fileName[-4:] == '.dll': # DLL
                    print(fileName)
                    MicrosoftDlls.add(fileName.lower())
                elif fileName[-4:] == '.exe': # EXE
                    GetPayload(path, fileName) # 生成 Payload
    except: # 文件夹无法打开
        pass

if __name__ == '__main__':
    if len(sys.argv) == 2:
        # 收集微软 DLL
        if os.path.exists('微软 DLL.txt'):
            with open('微软 DLL.txt','r') as f:
                MicrosoftDlls = f.read().splitlines() # ['ntdll.dll', 'kernel32.dll', ...]
        else:
            MicrosoftDlls = set() # {'ntdll.dll', 'kernel32.dll', ...}
            Scan('C:/Windows/System32', '.dll')
            Scan('C:/Windows/SysWOW64', '.dll')
            Scan('C:/Windows/WinSxS', '.dll')
            with open('微软 DLL.txt', 'w') as f:
                f.write('\n'.join(MicrosoftDlls))
        # 扫描 EXE
        Scan(sys.argv[1], '.exe')
    else:
        print('Usage: python scan.py "D:/"')
