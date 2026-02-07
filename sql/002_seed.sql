-- Seed data for testing SQL Proxy Service

-- Insert sample customers with PII
INSERT INTO customers (name, email, phone, address) VALUES
    ('John Doe', 'john.doe@example.com', '+1-555-0101', '123 Main St, New York, NY 10001'),
    ('Jane Smith', 'jane.smith@example.com', '+1-555-0102', '456 Oak Ave, Los Angeles, CA 90001'),
    ('Bob Johnson', 'bob.johnson@example.com', '+1-555-0103', '789 Pine Rd, Chicago, IL 60601'),
    ('Alice Williams', 'alice.williams@example.com', '+1-555-0104', '321 Elm St, Houston, TX 77001'),
    ('Charlie Brown', 'charlie.brown@example.com', '+1-555-0105', '654 Maple Dr, Phoenix, AZ 85001'),
    ('Diana Davis', 'diana.davis@example.com', '+1-555-0106', '987 Cedar Ln, Philadelphia, PA 19101'),
    ('Eve Martinez', 'eve.martinez@example.com', '+1-555-0107', '147 Birch Ct, San Antonio, TX 78201'),
    ('Frank Garcia', 'frank.garcia@example.com', '+1-555-0108', '258 Spruce Way, San Diego, CA 92101'),
    ('Grace Lee', 'grace.lee@example.com', '+1-555-0109', '369 Walnut Blvd, Dallas, TX 75201'),
    ('Henry Wilson', 'henry.wilson@example.com', '+1-555-0110', '741 Ash Ave, San Jose, CA 95101');

-- Insert sample orders
INSERT INTO orders (customer_id, order_number, amount, status) VALUES
    (1, 'ORD-2024-001', 99.99, 'completed'),
    (1, 'ORD-2024-002', 149.50, 'completed'),
    (2, 'ORD-2024-003', 299.99, 'completed'),
    (2, 'ORD-2024-004', 79.95, 'pending'),
    (3, 'ORD-2024-005', 199.99, 'completed'),
    (4, 'ORD-2024-006', 449.00, 'shipped'),
    (4, 'ORD-2024-007', 89.99, 'completed'),
    (5, 'ORD-2024-008', 159.50, 'pending'),
    (6, 'ORD-2024-009', 279.99, 'completed'),
    (7, 'ORD-2024-010', 99.00, 'shipped'),
    (8, 'ORD-2024-011', 349.99, 'completed'),
    (9, 'ORD-2024-012', 129.95, 'pending'),
    (10, 'ORD-2024-013', 199.00, 'completed');

-- Insert sample order items
INSERT INTO order_items (order_id, product_name, quantity, unit_price) VALUES
    (1, 'Laptop Stand', 1, 49.99),
    (1, 'Wireless Mouse', 1, 29.99),
    (1, 'USB-C Cable', 1, 19.99),
    (2, 'Monitor', 1, 149.50),
    (3, 'Mechanical Keyboard', 1, 129.99),
    (3, 'Desk Lamp', 1, 69.99),
    (3, 'Cable Organizer', 2, 49.99),
    (4, 'Webcam', 1, 79.95),
    (5, 'Headphones', 1, 199.99),
    (6, 'Standing Desk', 1, 449.00),
    (7, 'Office Chair Mat', 1, 89.99),
    (8, 'Laptop Bag', 1, 79.50),
    (8, 'Phone Stand', 2, 39.99),
    (9, 'External SSD', 1, 279.99),
    (10, 'Bluetooth Speaker', 1, 99.00),
    (11, 'Tablet', 1, 349.99),
    (12, 'Smart Watch', 1, 129.95),
    (13, 'Fitness Tracker', 1, 199.00);

-- Insert sensitive data (for access control testing)
INSERT INTO sensitive_data (customer_id, ssn, credit_card, salary, notes) VALUES
    (1, '123-45-6789', '4532-1234-5678-9010', 85000.00, 'VIP customer'),
    (2, '234-56-7890', '5425-2345-6789-0123', 72000.00, 'Frequent buyer'),
    (3, '345-67-8901', '4716-3456-7890-1234', 95000.00, NULL),
    (4, '456-78-9012', '5105-4567-8901-2345', 68000.00, 'Premium member'),
    (5, '567-89-0123', '4539-5678-9012-3456', 110000.00, 'Enterprise account');
