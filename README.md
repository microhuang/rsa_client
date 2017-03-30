# rsa_client


```
填充模式    密钥长度    输入分组有效载荷    输出分组长度
PKCS#1      768         85                  96
PKCS#1      1024        117                 128
PKCS#1      2048        245                 256
OAEP        768         54                  96
OAEP        1024        86                  128
OAEP        2048        214                 256
```

openssl版本对公钥格式的变化：

```在支付宝对接中，支付宝提供公钥为无换行格式。其中本地php(mac)环境中，加载公钥无误，服务器php(centos)环境中，加载失败。但改为标准的带有换行格式的公钥则在两个环境中均支持。猜测与openssl版本有关，验证如下：同一公钥，分别使用上述两种格式保持为pub1.key、pub2.key，用OpenSSL 1.0.2d验证，不支持无换行的公钥数据。OpenSSL 1.0.2j支持两种格式的数据。命令为：openssl rsautl -inkey pub1.key -pubin。```
