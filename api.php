<?php
// api.php — Backend نهایی فروشگاه داودی
declare(strict_types=1);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/helpers.php';

// --- HEADERS ---
header("Content-Type: application/json; charset=utf-8");

$allowed_origins = [
    'http://localhost',
    'http://127.0.0.1',
    'https://berenjdavoudi.ir'
];
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

        /* -------- Get CSRF Token -------- */
        case "getCsrfToken":
            requireAuth();
            jsonResponse(true, ['token' => getCsrfToken()], "CSRF Token");
            break;

        /* -------- Register -------- */
        case "register":
            $inputJSON = json_decode(file_get_contents('php://input'), true);
            $data = is_array($inputJSON) ? $inputJSON : $_POST;

            $name = trim($data['name'] ?? '');
            $phone = trim($data['phone'] ?? '');
            $password = $data['password'] ?? '';
            $email = trim($data['email'] ?? '');
            $referral = trim($data['referral'] ?? '');
            if (empty($email)) $email = null;

            if (!$name || !$phone || !$password) jsonResponse(false,null,"اطلاعات ناقص",400);

            $stmt=$pdo->prepare("SELECT id FROM users WHERE phone=?");
            $stmt->execute([$phone]);
            if($stmt->fetch()) jsonResponse(false,null,"این شماره قبلا ثبت شده",409);

            $refCode = generateReferralCode($phone);
            $referred_by=null;
            if($referral){
                $stmt=$pdo->prepare("SELECT id FROM users WHERE referral_code=?");
                $stmt->execute([$referral]);
                if($row=$stmt->fetch()) $referred_by=$row['id'];
            }

            $stmt=$pdo->prepare("INSERT INTO users (name,email,phone,password,referral_code,referred_by) VALUES (?,?,?,?,?,?)");
            $stmt->execute([$name,$email,$phone,password_hash($password,PASSWORD_BCRYPT),$refCode,$referred_by]);

            jsonResponse(true,['referral_code'=>$refCode],"ثبت‌نام موفق");
            break;

        /* -------- Login -------- */
        case "login":
            $inputJSON = json_decode(file_get_contents('php://input'), true);
            $data = is_array($inputJSON) ? $inputJSON : $_POST;

            $username=trim($data['username'] ?? '');
            $password=$data['password'] ?? '';
            if(!$username||!$password) jsonResponse(false,null,"اطلاعات ناقص",400);

            $stmt=$pdo->prepare("SELECT * FROM users WHERE phone=? OR email=? LIMIT 1");
            $stmt->execute([$username,$username]);
            $user=$stmt->fetch();
            if(!$user||!password_verify($password,$user['password'])) jsonResponse(false,null,"اطلاعات ورود اشتباه",401);

            $_SESSION['user_id']=$user['id'];
            session_regenerate_id(true);
            $_SESSION['csrf_token'] = bin2hex(random_bytes(24));

            jsonResponse(true,['id'=>$user['id'],'name'=>$user['name'],'referral_code'=>$user['referral_code']],"ورود موفق");
            break;

        /* -------- Logout -------- */
        case "logout":
            requireAuth();
            $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            if (!validateCsrfToken($csrfToken)) jsonResponse(false, null, 'درخواست نامعتبر', 403);

            $_SESSION = [];
            if (ini_get("session.use_cookies")) {
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params["path"], $params["domain"],
                    $params["secure"], $params["httponly"]
                );
            }
            session_destroy();
            jsonResponse(true, null, "خروج موفق");
            break;

        /* -------- Profile -------- */
        case "profile":
            requireAuth();
            $stmt=$pdo->prepare("
                SELECT u.id, u.name, u.email, u.phone, u.referral_code, u.province, u.city, u.postal_code,
                       (SELECT COUNT(*) FROM users WHERE referred_by = u.id) as referral_count
                FROM users u WHERE u.id = ?
            ");
            $stmt->execute([$_SESSION['user_id']]);
            $profileData = $stmt->fetch();
            if (!$profileData) jsonResponse(false, null, "کاربر یافت نشد", 404);
            jsonResponse(true, $profileData, "پروفایل");
            break;

        /* -------- Update Profile -------- */
        case "updateProfile":
            requireAuth();
            $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            if (!validateCsrfToken($csrfToken)) jsonResponse(false, null, 'درخواست نامعتبر', 403);

            $data = json_decode(file_get_contents('php://input'), true);
            $name = trim($data['name'] ?? '');
            $email = trim($data['email'] ?? '');
            $province = trim($data['province'] ?? '');
            $city = trim($data['city'] ?? '');
            $postal_code = trim($data['postal_code'] ?? '');

            if (!$name) jsonResponse(false, null, "نام نمی‌تواند خالی باشد", 400);

            $stmt = $pdo->prepare("UPDATE users SET name=?, email=?, province=?, city=?, postal_code=? WHERE id=?");
            $stmt->execute([$name,$email,$province,$city,$postal_code,$_SESSION['user_id']]);
            jsonResponse(true, null, "پروفایل بروزرسانی شد");
            break;

        /* -------- Products -------- */
        case "products":
            $stmt=$pdo->query("SELECT id,name,description,price,image,stock FROM products WHERE stock > 0");
            jsonResponse(true,$stmt->fetchAll(),"محصولات");
            break;

        /* -------- Product Detail -------- */
        case "product":
            $id=(int)($_GET['id']??0);
            $stmt=$pdo->prepare("SELECT id,name,description,price,image,stock FROM products WHERE id=?");
            $stmt->execute([$id]);
            $row=$stmt->fetch();
            if(!$row) jsonResponse(false,null,"یافت نشد",404);
            jsonResponse(true,$row,"محصول");
            break;

        /* -------- Create Order -------- */
        case "order":
            requireAuth();
            $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            if (!validateCsrfToken($csrfToken)) jsonResponse(false, null, 'درخواست نامعتبر', 403);

            $data = json_decode(file_get_contents('php://input'), true);
            $items = $data['items'] ?? [];
            $payment = $data['payment'] ?? 'cod';
            if (!$items) jsonResponse(false, null, "سبد خرید خالی است", 400);

            $userId = $_SESSION['user_id'];
            $pdo->beginTransaction();
            try {
                $total = 0;
                foreach ($items as $it) {
                    $pid = (int)$it['id']; $qty = (int)$it['quantity'];
                    $stmt = $pdo->prepare("SELECT price, stock, name FROM products WHERE id=? FOR UPDATE");
                    $stmt->execute([$pid]);
                    $row = $stmt->fetch();
                    if (!$row || $row['stock'] < $qty) throw new Exception("موجودی محصول " . ($row['name'] ?? '') . " کافی نیست.");
                    $total += $row['price'] * $qty;
                }

                // تخفیف‌ها
                $stmtDisc = $pdo->prepare("SELECT SUM(amount) as total FROM discounts WHERE user_id=?");
                $stmtDisc->execute([$userId]);
                $discountApplied = $stmtDisc->fetch()['total'] ?? 0;
                $finalTotal = max(0, $total - $discountApplied);

                // آدرس
                $address_id = (int)($data['address_id'] ?? 0);
                $addressText = $data['address'] ?? null;
                if ($address_id > 0) {
                    $stmt = $pdo->prepare("SELECT address FROM addresses WHERE id=? AND user_id=?");
                    $stmt->execute([$address_id, $userId]);
                    $row = $stmt->fetch();
                    if (!$row) throw new Exception("آدرس انتخابی یافت نشد");
                    $addressToUse = $row['address'];
                } else {
                    $province = trim($data['province'] ?? '');
                    $city = trim($data['city'] ?? '');
                    $postal_code = trim($data['postal_code'] ?? '');
                    if (!$addressText || !$province || !$city) throw new Exception("اطلاعات آدرس ناقص است");
                    $addressToUse = $province . " - " . $city . " - " . $addressText;
                    $is_default = !empty($data['saveAsDefault']) ? 1 : 0;
                    if ($is_default) {
                        $pdo->prepare("UPDATE addresses SET is_default=0 WHERE user_id=?")->execute([$userId]);
                    }
                    $stmt = $pdo->prepare("INSERT INTO addresses (user_id, province, city, postal_code, address, is_default) VALUES (?,?,?,?,?,?)");
                    $stmt->execute([$userId,$province,$city,$postal_code,$addressText,$is_default]);
                }

                $stmt = $pdo->prepare("INSERT INTO orders (user_id,total_amount,address,payment_method,status) VALUES (?,?,?,?, 'در حال پردازش')");
                $stmt->execute([$userId,$finalTotal,$addressToUse,$payment]);
                $orderId = $pdo->lastInsertId();

                $stmtItem = $pdo->prepare("INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?,?,?,?)");
                $stmtStock = $pdo->prepare("UPDATE products SET stock = stock - ? WHERE id=?");
                foreach ($items as $it) {
                    $pid = (int)$it['id']; $qty = (int)$it['quantity'];
                    $stmtPrice = $pdo->prepare("SELECT price FROM products WHERE id=?");
                    $stmtPrice->execute([$pid]);
                    $price = $stmtPrice->fetch()['price'];
                    $stmtItem->execute([$orderId,$pid,$qty,$price]);
                    $stmtStock->execute([$qty,$pid]);
                }

                if ($discountApplied > 0) {
                    $stmtDeleteDisc = $pdo->prepare("DELETE FROM discounts WHERE user_id=?");
                    $stmtDeleteDisc->execute([$userId]);
                }

                $pdo->commit();
                jsonResponse(true, ['order_id'=>$orderId,'discount_applied'=>$discountApplied], "سفارش ثبت شد");
            } catch (Exception $e) {
                $pdo->rollBack();
                jsonResponse(false,null,"خطا: ".$e->getMessage(),500);
            }
            break;

        /* -------- Orders -------- */
        case "orders":
            requireAuth();
            $stmt = $pdo->prepare("SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC");
            $stmt->execute([$_SESSION['user_id']]);
            $orders = $stmt->fetchAll();
            if (!$orders) jsonResponse(true,[],"سفارش‌ها");

            $orderIds = array_column($orders,'id');
            $placeholders = implode(',', array_fill(0,count($orderIds),'?'));
            $stmtItem = $pdo->prepare("SELECT oi.order_id, oi.product_id, p.name as product_name, oi.quantity, oi.price 
                                       FROM order_items oi JOIN products p ON oi.product_id=p.id WHERE oi.order_id IN ($placeholders)");
            $stmtItem->execute($orderIds);
            $allItems = $stmtItem->fetchAll();

            $itemsByOrderId = [];
            foreach ($allItems as $item) {
                $itemsByOrderId[$item['order_id']][] = $item;
            }
            foreach ($orders as &$o) {
                $o['items'] = $itemsByOrderId[$o['id']] ?? [];
            }
            jsonResponse(true,$orders,"سفارش‌ها");
            break;

        /* -------- Discounts -------- */
        case "discounts":
            requireAuth();
            $stmt=$pdo->prepare("SELECT * FROM discounts WHERE user_id=? ORDER BY created_at DESC");
            $stmt->execute([$_SESSION['user_id']]);
            jsonResponse(true,$stmt->fetchAll(),"تخفیف‌ها");
            break;

        case "getDiscountsTotal":
            requireAuth();
            $stmt=$pdo->prepare("SELECT SUM(amount) as total FROM discounts WHERE user_id=?");
            $stmt->execute([$_SESSION['user_id']]);
            $result=$stmt->fetch();
            $totalDiscounts = $result['total'] ?? 0;
            jsonResponse(true,['total'=>(int)$totalDiscounts],"مجموع تخفیف‌ها");
            break;

        /* -------- Addresses -------- */
        case "getAddresses":
            requireAuth();
            $stmt=$pdo->prepare("SELECT id,province,city,postal_code,address,is_default FROM addresses WHERE user_id=? ORDER BY is_default DESC, created_at DESC");
            $stmt->execute([$_SESSION['user_id']]);
            jsonResponse(true,$stmt->fetchAll(),"آدرس‌ها");
            break;

        case "addAddress":
            requireAuth();
            $csrfToken=$_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            if(!validateCsrfToken($csrfToken)) jsonResponse(false,null,'درخواست نامعتبر',403);

            $data=json_decode(file_get_contents('php://input'),true);
            $province=trim($data['province']??'');
            $city=trim($data['city']??'');
            $postal_code=trim($data['postal_code']??'');
            $address=trim($data['address']??'');
            $is_default=!empty($data['is_default'])?1:0;
            if(!$province||!$city||!$address) jsonResponse(false,null,"اطلاعات ناقص",400);

            if($is_default) $pdo->prepare("UPDATE addresses SET is_default=0 WHERE user_id=?")->execute([$_SESSION['user_id']]);
            $stmt=$pdo->prepare("INSERT INTO addresses (user_id,province,city,postal_code,address,is_default) VALUES (?,?,?,?,?,?)");
            $stmt->execute([$_SESSION['user_id'],$province,$city,$postal_code,$address,$is_default]);
            jsonResponse(true,['id'=>$pdo->lastInsertId()],"آدرس ذخیره شد");
            break;

        case "updateAddress":
            requireAuth();
            $csrfToken=$_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            if(!validateCsrfToken($csrfToken)) jsonResponse(false,null,'درخواست نامعتبر',403);

            $data=json_decode(file_get_contents('php://input'),true);
            $id=(int)($data['id']??0);
            $province=trim($data['province']??'');
            $city=trim($data['city']??'');
            $postal_code=trim($data['postal_code']??'');
            $address=trim($data['address']??'');
            $is_default=!empty($data['is_default'])?1:0;
            if(!$id||!$province||!$city||!$address) jsonResponse(false,null,"اطلاعات ناقص",400);

            if($is_default) $pdo->prepare("UPDATE addresses SET is_default=0 WHERE user_id=?")->execute([$_SESSION['user_id']]);
            $stmt=$pdo->prepare("UPDATE addresses SET province=?,city=?,postal_code=?,address=?,is_default=? WHERE id=? AND user_id=?");
            $stmt->execute([$province,$city,$postal_code,$address,$is_default,$id,$_SESSION['user_id']]);
            jsonResponse(true,null,"آدرس بروزرسانی شد");
            break;

        case "deleteAddress":
            requireAuth();
            $csrfToken=$_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            if(!validateCsrfToken($csrfToken)) jsonResponse(false,null,'درخواست نامعتبر',403);

            $data=json_decode(file_get_contents('php://input'),true);
            $id=(int)($data['id']??0);
            if(!$id) jsonResponse(false,null,"شناسه آدرس نامعتبر",400);

            $stmt=$pdo->prepare("DELETE FROM addresses WHERE id=? AND user_id=?");
            $stmt->execute([$id,$_SESSION['user_id']]);
            jsonResponse(true,null,"آدرس حذف شد");
            break;

        default:
            jsonResponse(false,null,"درخواست نامعتبر",400);
    }
} catch(Exception $ex){
    error_log("API Error: ".$ex->getMessage());
    jsonResponse(false,null,"خطای سرور",500);
}
