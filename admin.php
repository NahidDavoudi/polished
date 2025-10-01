<?php
// admin.php
declare(strict_types=1);
require_once __DIR__ . '/helpers.php';

// بررسی آیا کاربر ادمین است
requireAdmin();

header("Content-Type: application/json; charset=utf-8");

// CORS headers مشابه api.php
$allowed_origins = ['http://localhost', 'http://127.0.0.1', 'https://berenjdavoudi.ir'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: {$origin}");
}
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Headers: Content-Type, X-CSRF-Token");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE");
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

$action = $_GET['action'] ?? '';

try {
    switch ($action) {
        
        /* -------- آمار کلی -------- */
        case "dashboardStats":
            $stats = [];
            
            // تعداد کاربران
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM users");
            $stats['total_users'] = $stmt->fetch()['count'];
            
            // تعداد سفارشات
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM orders");
            $stats['total_orders'] = $stmt->fetch()['count'];
            
            // تعداد محصولات
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM products");
            $stats['total_products'] = $stmt->fetch()['count'];
            
            // درآمد کل
            $stmt = $pdo->query("SELECT SUM(total_amount) as total FROM orders WHERE status='تحویل شد'");
            $stats['total_revenue'] = $stmt->fetch()['total'] ?? 0;
            
            jsonResponse(true, $stats, "آمار dashboard");
            break;

        /* -------- مدیریت کاربران -------- */
        case "getUsers":
            $page = max(1, (int)($_GET['page'] ?? 1));
            $limit = 20;
            $offset = ($page - 1) * $limit;
            
            $stmt = $pdo->prepare("
                SELECT id, name, email, phone, referral_code, referred_by, created_at 
                FROM users 
                ORDER BY created_at DESC 
                LIMIT ? OFFSET ?
            ");
            $stmt->execute([$limit, $offset]);
            $users = $stmt->fetchAll();
            
            // تعداد کل کاربران
            $stmt = $pdo->query("SELECT COUNT(*) as total FROM users");
            $total = $stmt->fetch()['total'];
            
            jsonResponse(true, [
                'users' => $users,
                'pagination' => [
                    'page' => $page,
                    'limit' => $limit,
                    'total' => $total,
                    'pages' => ceil($total / $limit)
                ]
            ], "لیست کاربران");
            break;

        /* -------- مدیریت محصولات -------- */
        case "getProducts":
            $stmt = $pdo->query("SELECT * FROM products ORDER BY created_at DESC");
            jsonResponse(true, $stmt->fetchAll(), "لیست محصولات");
            break;

        case "addProduct":
            $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            if (!validateCsrfToken($csrfToken)) jsonResponse(false, null, 'درخواست نامعتبر', 403);

            $data = json_decode(file_get_contents('php://input'), true);
            $name = trim($data['name'] ?? '');
            $description = trim($data['description'] ?? '');
            $price = (float)($data['price'] ?? 0);
            $stock = (int)($data['stock'] ?? 0);
            $image = trim($data['image'] ?? '');

            if (!$name || $price <= 0) jsonResponse(false, null, "اطلاعات محصول ناقص", 400);

            $stmt = $pdo->prepare("
                INSERT INTO products (name, description, price, stock, image) 
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([$name, $description, $price, $stock, $image]);
            
            jsonResponse(true, ['id' => $pdo->lastInsertId()], "محصول اضافه شد");
            break;

        case "updateProduct":
            $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            if (!validateCsrfToken($csrfToken)) jsonResponse(false, null, 'درخواست نامعتبر', 403);

            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $name = trim($data['name'] ?? '');
            $description = trim($data['description'] ?? '');
            $price = (float)($data['price'] ?? 0);
            $stock = (int)($data['stock'] ?? 0);
            $image = trim($data['image'] ?? '');

            if (!$id || !$name || $price <= 0) jsonResponse(false, null, "اطلاعات محصول ناقص", 400);

            $stmt = $pdo->prepare("
                UPDATE products 
                SET name=?, description=?, price=?, stock=?, image=?, updated_at=NOW() 
                WHERE id=?
            ");
            $stmt->execute([$name, $description, $price, $stock, $image, $id]);
            
            jsonResponse(true, null, "محصول به‌روزرسانی شد");
            break;

        case "deleteProduct":
            $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            if (!validateCsrfToken($csrfToken)) jsonResponse(false, null, 'درخواست نامعتبر', 403);

            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);

            if (!$id) jsonResponse(false, null, "شناسه محصول نامعتبر", 400);

            // بررسی اینکه محصول در سفارشات استفاده نشده
            $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM order_items WHERE product_id=?");
            $stmt->execute([$id]);
            $used = $stmt->fetch()['count'];
            
            if ($used > 0) {
                jsonResponse(false, null, "این محصول در سفارشات استفاده شده و قابل حذف نیست", 400);
            }

            $stmt = $pdo->prepare("DELETE FROM products WHERE id=?");
            $stmt->execute([$id]);
            
            jsonResponse(true, null, "محصول حذف شد");
            break;

        /* -------- مدیریت سفارشات -------- */
        case "getOrders":
            $page = max(1, (int)($_GET['page'] ?? 1));
            $limit = 20;
            $offset = ($page - 1) * $limit;
            
            $stmt = $pdo->prepare("
                SELECT o.*, u.name as user_name, u.phone as user_phone 
                FROM orders o 
                LEFT JOIN users u ON o.user_id = u.id 
                ORDER BY o.created_at DESC 
                LIMIT ? OFFSET ?
            ");
            $stmt->execute([$limit, $offset]);
            $orders = $stmt->fetchAll();
            
            // آیتم‌های سفارشات
            if ($orders) {
                $orderIds = array_column($orders, 'id');
                $placeholders = implode(',', array_fill(0, count($orderIds), '?'));
                $stmtItems = $pdo->prepare("
                    SELECT oi.*, p.name as product_name 
                    FROM order_items oi 
                    JOIN products p ON oi.product_id = p.id 
                    WHERE oi.order_id IN ($placeholders)
                ");
                $stmtItems->execute($orderIds);
                $items = $stmtItems->fetchAll();
                
                $itemsByOrder = [];
                foreach ($items as $item) {
                    $itemsByOrder[$item['order_id']][] = $item;
                }
                
                foreach ($orders as &$order) {
                    $order['items'] = $itemsByOrder[$order['id']] ?? [];
                }
            }
            
            $stmt = $pdo->query("SELECT COUNT(*) as total FROM orders");
            $total = $stmt->fetch()['total'];
            
            jsonResponse(true, [
                'orders' => $orders,
                'pagination' => [
                    'page' => $page,
                    'limit' => $limit,
                    'total' => $total,
                    'pages' => ceil($total / $limit)
                ]
            ], "لیست سفارشات");
            break;

        case "updateOrderStatus":
            $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            if (!validateCsrfToken($csrfToken)) jsonResponse(false, null, 'درخواست نامعتبر', 403);

            $data = json_decode(file_get_contents('php://input'), true);
            $orderId = (int)($data['order_id'] ?? 0);
            $status = trim($data['status'] ?? '');

            $allowedStatuses = ['در حال پردازش', 'تایید شده', 'در حال ارسال', 'تحویل شد', 'لغو شده'];
            if (!$orderId || !in_array($status, $allowedStatuses)) {
                jsonResponse(false, null, "وضعیت نامعتبر", 400);
            }

            $stmt = $pdo->prepare("UPDATE orders SET status=?, updated_at=NOW() WHERE id=?");
            $stmt->execute([$status, $orderId]);
            
            jsonResponse(true, null, "وضعیت سفارش به‌روزرسانی شد");
            break;

        /* -------- مدیریت تخفیف‌ها -------- */
        case "addDiscount":
            $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            if (!validateCsrfToken($csrfToken)) jsonResponse(false, null, 'درخواست نامعتبر', 403);

            $data = json_decode(file_get_contents('php://input'), true);
            $userId = (int)($data['user_id'] ?? 0);
            $amount = (int)($data['amount'] ?? 0);
            $reason = trim($data['reason'] ?? '');

            if (!$userId || $amount <= 0) jsonResponse(false, null, "اطلاعات تخفیف ناقص", 400);

            // بررسی وجود کاربر
            $stmt = $pdo->prepare("SELECT id FROM users WHERE id=?");
            $stmt->execute([$userId]);
            if (!$stmt->fetch()) jsonResponse(false, null, "کاربر یافت نشد", 404);

            $stmt = $pdo->prepare("INSERT INTO discounts (user_id, amount, reason) VALUES (?, ?, ?)");
            $stmt->execute([$userId, $amount, $reason]);
            
            jsonResponse(true, ['id' => $pdo->lastInsertId()], "تخفیف اضافه شد");
            break;

        default:
            jsonResponse(false, null, "درخواست نامعتبر", 400);
    }
} catch(Exception $ex) {
    error_log("Admin API Error: " . $ex->getMessage());
    jsonResponse(false, null, "خطای سرور", 500);
}
?>