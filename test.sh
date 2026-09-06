#!/bin/bash
# 图床 API 测试脚本
# 用法: bash test.sh <管理密码> <密钥>

DOMAIN="https://img.ani-nya.com"
PASS="${1:-changeme}"
KEY="$2"

echo "=== 图床 API 测试 ==="
echo "域名: $DOMAIN"
echo ""

# 1. 首页
echo "[1] 测试首页..."
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$DOMAIN/")
if [ "$CODE" = "200" ]; then
    echo "  ✅ 首页正常 ($CODE)"
else
    echo "  ❌ 首页异常 ($CODE)"
fi

# 2. 登录
echo "[2] 测试登录..."
LOGIN=$(curl -s -c /tmp/imgbed_cookies.txt -X POST "$DOMAIN/index.php?_route=/api/login" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"$PASS\"}")
if echo "$LOGIN" | grep -q '"ok":true'; then
    echo "  ✅ 登录成功"
else
    echo "  ❌ 登录失败: $LOGIN"
    exit 1
fi

# 3. 生成密钥
if [ -z "$KEY" ]; then
    echo "[3] 生成密钥..."
    GEN=$(curl -s -b /tmp/imgbed_cookies.txt -X POST "$DOMAIN/index.php?_route=/api/keys" \
        -H "Content-Type: application/json" \
        -d '{"note":"test"}')
    KEY=$(echo "$GEN" | grep -o '"key":"[^"]*"' | cut -d'"' -f4)
    if [ -n "$KEY" ]; then
        echo "  ✅ 密钥: $KEY"
    else
        echo "  ❌ 生成失败: $GEN"
        exit 1
    fi
else
    echo "[3] 使用已有密钥: $KEY"
fi

# 4. 上传图片
echo "[4] 测试上传..."
# 创建测试图片
convert -size 100x100 xc:red /tmp/imgbed_test.png 2>/dev/null || python3 -c "
from PIL import Image
img = Image.new('RGB', (100, 100), 'red')
img.save('/tmp/imgbed_test.png')
" 2>/dev/null || echo -n $'\x89PNG\r\n\x1a\n' > /tmp/imgbed_test.png

UPLOAD=$(curl -s -X POST "$DOMAIN/upload" \
    -H "Authorization: Bearer $KEY" \
    -F "file=@/tmp/imgbed_test.png")
URL=$(echo "$UPLOAD" | grep -o '"url":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -n "$URL" ]; then
    echo "  ✅ 上传成功"
    echo "  URL: $URL"
else
    echo "  ❌ 上传失败: $UPLOAD"
    exit 1
fi

# 5. 访问图片
echo "[5] 测试访问图片..."
IMG_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
if [ "$IMG_CODE" = "200" ]; then
    echo "  ✅ 图片可访问 ($IMG_CODE)"
else
    echo "  ❌ 图片不可访问 ($IMG_CODE)"
fi

# 6. 列出图片
echo "[6] 测试图片列表..."
LIST=$(curl -s -b /tmp/imgbed_cookies.txt "$DOMAIN/index.php?_route=/api/images")
COUNT=$(echo "$LIST" | grep -o '"filename"' | wc -l)
echo "  图片数量: $COUNT"

# 7. 删除图片
echo "[7] 测试删除图片..."
FILENAME=$(basename "$URL")
DEL=$(curl -s -b /tmp/imgbed_cookies.txt -X DELETE "$DOMAIN/index.php?_route=/api/images/$FILENAME")
if echo "$DEL" | grep -q '"ok":true'; then
    echo "  ✅ 删除成功"
else
    echo "  ❌ 删除失败: $DEL"
fi

echo ""
echo "=== 测试完成 ==="
rm -f /tmp/imgbed_cookies.txt /tmp/imgbed_test.png
