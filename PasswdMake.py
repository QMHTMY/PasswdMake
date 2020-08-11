#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   Date: 2020-07-31
#   Author: Shieber
#   密码生成器

import sys
import base64
from os.path import basename
__version__ = 0.1
__all__ = ['HashMn', 'HashPassword']


"""密码生成脚本
   利用关键字符串(种子)和梅森哈希数去产生各种种子不同长度的密码。
   种子:用户输入的某账户的关键字符串，比如对应腾讯的QQ，种子可以是[qq,qQ,Qq,QQ,txqq,..]中任何一个。
   种子建议大于四个字符，这样产生的密码才够健壮。
   梅森素数:形如Mn=2^n-1的素数，n为素数，此脚本用来产生哈希数。
"""

##函数的配置参数，可放入类，也可单独放到文件中，如yaml文件，此文档未做处理
#1.密码及操作控制字典
# trunctLen  运算中舍去的子字符串长度
controlkey = {'minseedLen':4,'trunctLen':2,'minpswdLen':6,'maxpswdLen':20}

#2.密码长度控制表，最短6位，最长20位，
# 此表主要用于设置哈希数的次方数k，因为不求高次幂，数太小，长度就不够。
# 6-10位长度时，求1次方
lengthmap = {
        '6':1, '7':1, '8':1, '9':1, '10':1,
        '11':2,'12':2,'13':2,'14':2,'15':2,
        '16':3,'17':3,'18':3,'19':3,'20':3
       }

#3.使用可见的ascii字符来做密码子，可自行改变顺序和增删字符
# 哈希函数计算高次幂后，每次截取2位字符转换为整数(00-99)，然后映射到secretstr不同位置的值作为密码子
# secretstr中的ascill包括[0-9],[a-z],[A-Z],+-*/%\[]{}()^.?':;共91位
secretstr = "!pqr$*+STU%Vstuv:w'{WX&YZ-Q_/02.3(4<AlBCo|xy8jDE^FG?IH[\]JK>LM#N6OP);Ra@bce7d=9fg5hi,k1mnz}"

def hashMn(item):
    """梅森哈希函数：将item中各字符ascii值求和，同时不同位置ascii值乘以不同权重(i+1)"""
    assert isinstance(item, str), f'item = {item} must be string'

    hashvalue = 0
    for i, c in enumerate(item):
        hashvalue += (i+1) * ord(c)

    #使用127位梅森素数计算哈希值，也可用第五位梅森素数8191
    return pow(hashvalue % 127, 3) - 1

def hashPassword(seed, bit=16):
    """由哈希数的k次方值产生密码, seed为种子，bit为密码长度[最小为6，默认为16]

       流程：
           a.由seed调用hashMn产生哈希数hashvalue
           b.依据bit的值，求哈希数的k次方，主要为了构造一个足够长的数
           c.将此足够长的数转换为字符串hashstr
           d.每次截取此字符串的2个字符(0-99)并转换为数字作为secretstr的位置参数pos
           e.若pos超过secretstr最大长度，则求余以转换到长度范围内
           f.依据pos，取出secretstr中一个字符作为密码字符拼接到password字符串
           g.将hashstr截短2位，若不为空字符串，则回到d步，直到生成整个密码password
           i.依据bit，截取password中前bit位返回，作为用户最终的密码

        此算法步骤繁复，好处在难以破解，极难出现冲突，用于产生个人密码完全没问题。
        当然，其中的数学函数个人可以修改，如此也适合自己的要求
    """
    assert len(seed) >= controlkey['minseedLen'], f'seed = {seed} must have length >= 4'
    assert isinstance(bit, int), f'bit = {bit} must be an integer'
    assert controlkey['maxpswdLen'] >= bit >= controlkey['minpswdLen'], f'password length must in 6-20'

    #获取hashvalue高次幂并转换位字符串hashstr
    hashvalue = hashMn(seed)
    k = lengthmap[str(bit)]
    hashstr = str(pow(hashvalue, k))

    #逐步获取密码子并组合成字符串
    passwd = ''
    while hashstr != '':
        pos = int(hashstr[:controlkey['trunctLen']])
        pos = pos % len(secretstr) if pos >= len(secretstr) else pos
        passwd += secretstr[pos]
        hashstr = hashstr[controlkey['trunctLen']:]
    
    #将seed扩充到passwd
    passwd = passwd.join(seed)

    #用base64转换passwd为64个可见字符[a-zA-Z0-9+/]并把+/转换为*#
    passwd = base64.b64encode(passwd.encode('utf-8'))
    passwd = str(passwd).replace('+','*').replace('/','#')

    #组合seed和密码返回，前两位为base64转换遗留的b'，需要舍去
    passwd = seed + ': ' + passwd[2:int(bit)+2]
    return passwd

if __name__ == "__main__":
    if len(sys.argv) == 3:
        seed = sys.argv[1]
        length  = int(sys.argv[2])
    elif len(sys.argv) == 2:
        seed = sys.argv[1]
        length  = 16
    else:
        print(f"Usage: {basename(sys.argv[0])} seed [length]")
        sys.exit(1)

    print(hashPassword(seed, length))
