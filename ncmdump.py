import binascii
import struct
import base64
import json
import os
from Crypto.Cipher import AES


def dump(file_path):
    # 687A4852416D736F356B496E62617857 (Hex) -> hzHRAmso5kInbaxW    (Text)
    core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    # 2331346C6A6B5F215C5D2630553C2728 (Hex) -> #14ljk_!\]&0U<'(    (Text)
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    # 定义 lambda 表达式
    unpad = lambda s: s[0:-(s[-1] if type(s[-1]) == int else ord(s[-1]))]
    # 以二进制读模式打开传入的 ncm 文件
    f = open(file_path, 'rb')
    # 读八字节
    header = f.read(8)
    # 确认其为 ncm 格式标记
    assert binascii.b2a_hex(header) == b'4354454e4644414d'
    # 后移 2 字节（多余字节）
    f.seek(2, 1)
    # 读四字节
    key_length = f.read(4)
    # 以小端方式转换 key_length 为 integer
    # 80 00 00 00 (Hex) -> 128 (int)
    key_length = struct.unpack('<I', bytes(key_length))[0]
    # 向后读文件的 128 字节
    key_data = f.read(key_length)
    # 将 key_data 转化为字符数组
    key_data_array = bytearray(key_data)
    # 将 key_data_array 中的每个字节与 0x64 做异或运算
    for i in range(0, len(key_data_array)): key_data_array[i] ^= 0x64
    # 将 bytearray key_data_array 转型为 bytes
    key_data = bytes(key_data_array)
    # 使用之前定义的 core_key 创建了 AES_ECB 解密器 cryptor
    cryptor = AES.new(core_key, AES.MODE_ECB)
    # 首先看 cryptor.decrypt(key_data)：解析 key_data，解析出来的数据开头是 neteasecloudmusic，即 ncm 的全称
    # 通过开头定义的 lambda 函数 unpad 去掉末尾的 \r 和开头的 neteasecloudmusic
    # 17 为 len("neteasecloudmusic")
    key_data = unpad(cryptor.decrypt(key_data))[17:]
    # 更新 key_length 的值（即 data 的长度）
    key_length = len(key_data)

    # 将 key_data 转型为 bytearray 类型
    key_data = bytearray(key_data)

    # 以下是 RC4-KSA 算法
    key_box = bytearray(range(256))
    c = 0
    last_byte = 0
    key_offset = 0
    for i in range(256):
        swap = key_box[i]
        c = (swap + last_byte + key_data[key_offset]) & 0xff
        key_offset += 1
        if key_offset >= key_length: key_offset = 0
        key_box[i] = key_box[c]
        key_box[c] = swap
        last_byte = c

    # 读取四字节长度，和前面的 key_length 相似
    meta_length = f.read(4)
    # 以小端方式将 meta_length 转化为 int
    meta_length = struct.unpack('<I', bytes(meta_length))[0]
    # 读取 meta_kength 字节长度数据赋给 meta_data
    meta_data = f.read(meta_length)
    # 类型转换
    meta_data_array = bytearray(meta_data)
    # 与 0x63 做异或
    for i in range(0, len(meta_data_array)): meta_data_array[i] ^= 0x63
    # 转型
    meta_data = bytes(meta_data_array)
    # 这里可以打断点看下 meta_data 的值，开头是 "163 key(Don't modify):"，共 22 位
    # 这里去掉无关的前 22 位然后使用 base64 解码
    meta_data = base64.b64decode(meta_data[22:])
    # 再和上面类似，构造 ECB 进行解密
    cryptor = AES.new(meta_key, AES.MODE_ECB)
    # 此处 meta_data 的一个参考数据：
    # b'music:{"musicId":441491828,"musicName":"\xe6\xb0\xb4\xe6\x98\x9f\xe8\xae\xb0","artist":[["\xe9\x83\xad\xe9\xa1\xb6",2843]],"albumId":35005583,"album":"\xe9\xa3\x9e\xe8\xa1\x8c\xe5\x99\xa8\xe7\x9a\x84\xe6\x89\xa7\xe8\xa1\x8c\xe5\x91\xa8\xe6\x9c\x9f","albumPicDocId":2946691248081599,"albumPic":"https://p4.music.126.net/wSMfGvFzOAYRU_yVIfquAA==/2946691248081599.jpg","bitrate":320000,"mp3DocId":"668809cf9ba99c3b7cc51ae17a66027f","duration":325266,"mvId":5404031,"alias":[],"transNames":[],"format":"mp3"}\r\r\r\r\r\r\r\r\r\r\r\r\r'
    # 去掉前六位 "music:"
    meta_data = unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
    # 转换成 json
    meta_data = json.loads(meta_data)

    # CRC32 校验码
    crc32 = f.read(4)
    crc32 = struct.unpack('<I', bytes(crc32))[0]
    # 后移五字节
    f.seek(5, 1)
    # 获取歌曲封面大小
    image_size = f.read(4)
    # 以小端方式将读取到的 Hex 数据转换成 int
    image_size = struct.unpack('<I', bytes(image_size))[0]
    # 读封面大小长度的数据，赋值给 image_data
    image_data = f.read(image_size)
    # 从之前构造的 json 中取歌曲名和文件拓展名，赋给 file_name
    file_name = meta_data['musicName'] + '.' + meta_data['format']
    # 以二进制写方式打开要生成的文件（若文件不存在会自动创建）
    m = open(os.path.join(os.path.split(file_path)[0], file_name), 'wb')
    chunk = bytearray()

    # 以下是 RC4-PRGA 算法，进行还原并输出文件
    while True:
        chunk = bytearray(f.read(0x8000))
        chunk_length = len(chunk)
        if not chunk:
            break
        for i in range(1, chunk_length + 1):
            j = i & 0xff;
            chunk[i - 1] ^= key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]
        m.write(chunk)
    m.close()
    f.close()


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1:
        for file_path in sys.argv[1:]:
            try:
                dump(file_path)
            except:
                pass
    else:
        print("Usage: python ncmdump.py \"File Name\"")
