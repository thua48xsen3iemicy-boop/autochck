# Порталы

Четыре статических сайта и конфиги nginx для них.

| Каталог | Сайт | Конфиг |
|---|---|---|
| `shop/` | Магазин посуды, `shop.lab` | `nginx/shop.conf` |
| `blog/` | Блог разработчика, `blog.lab` | `nginx/blog.conf` |
| `wiki/` | Вики по Linux, `wiki.lab` | `nginx/wiki.conf` |
| `news/` | Новости колледжа, `news.lab` | `nginx/news.conf` |

Конфиги рассчитаны на то, что репозиторий склонирован в `/var/www/portals`:
у сайта `shop` root — `/var/www/portals/shop` и т. д. Чтобы включить сайт на
сервере, подключите его конфиг в `/etc/nginx/conf.d/` и перезагрузите nginx.
