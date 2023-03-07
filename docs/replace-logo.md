# KubeClipper 定制项目 Logo 和 Title 方案

需要被替换的文件均位于打包生成的 dist 根目录下

## 替换 logo

替换 logo 涉及两个文件, favicon.ico 和 logo.svg， 位置在前端文件包根目录下，图片名和规格如下：

| 编号 | 图片名      | 建议像素尺寸 | 对应位置                                                     |
| ---- | ----------- | ------------ | ------------------------------------------------------------ |
| 1    | favicon.ico | 16*16        | 浏览器标签栏的 icon                                           |
| 2    | logo.svg    | 36*36        | 左侧菜单栏上方的logo(背景色是黑色，建议使用其浅色背景图片，如：白色、蓝色等) |

## 替换 Title

替换 title 涉及的文件是 `global.config.js`，位置在前端文件包根目录下，修改该 js 文件中的 title 值即可。

```js
const global_config={title:"KubeClipper",terminalTimeOut:15};
```
