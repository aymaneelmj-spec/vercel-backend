#!/usr/bin/env python3
"""
AI Service for Happy Deal Transit ERP
Provides transaction categorization, anomaly detection, and forecasting
"""

def categorize_transaction(description):
    """
    Categorize a transaction based on its description
    Returns a category string
    """
    description = description.lower()
    
    # Category keywords mapping
    categories = {
        'Salaries': ['salary', 'payroll', 'wage', 'employee', 'staff'],
        'Rent': ['rent', 'lease', 'property'],
        'Utilities': ['electricity', 'water', 'gas', 'internet', 'phone', 'utility'],
        'Transportation': ['fuel', 'gas', 'transport', 'vehicle', 'car', 'truck'],
        'Office Supplies': ['office', 'supplies', 'stationery', 'paper'],
        'Marketing': ['marketing', 'advertising', 'promotion', 'ad'],
        'Travel': ['travel', 'hotel', 'flight', 'accommodation'],
        'Meals': ['meal', 'lunch', 'dinner', 'restaurant', 'food'],
        'Insurance': ['insurance', 'coverage'],
        'Maintenance': ['maintenance', 'repair', 'service'],
        'Sales': ['sale', 'revenue', 'income', 'customer payment'],
        'Other': []
    }
    
    # Check each category
    for category, keywords in categories.items():
        for keyword in keywords:
            if keyword in description:
                return category
    
    return 'Other'


def detect_anomalies(transactions):
    """
    Detect anomalous transactions
    Returns a list of anomaly dictionaries
    """
    if not transactions or len(transactions) < 5:
        return []
    
    anomalies = []
    
    # Calculate average transaction amount
    amounts = [t.amount_mad for t in transactions if t.type == 'expense']
    if not amounts:
        return []
    
    avg_amount = sum(amounts) / len(amounts)
    std_dev = (sum((x - avg_amount) ** 2 for x in amounts) / len(amounts)) ** 0.5
    
    # Detect anomalies (transactions > 2 standard deviations from mean)
    threshold = avg_amount + (2 * std_dev)
    
    for transaction in transactions:
        if transaction.type == 'expense' and transaction.amount_mad > threshold:
            anomalies.append({
                'id': transaction.id,
                'date': transaction.date.isoformat(),
                'description': transaction.description,
                'amount': transaction.amount_mad,
                'average': round(avg_amount, 2),
                'deviation': round((transaction.amount_mad - avg_amount) / std_dev, 2),
                'reason': 'Unusually high amount'
            })
    
    return anomalies[:10]  # Return top 10 anomalies


def forecast_cash_flow(dates, amounts, steps=30):
    """
    Forecast future cash flow based on historical data
    Returns a list of forecasted amounts
    """
    if not amounts or len(amounts) < 2:
        return [0] * steps
    
    # Simple moving average forecast
    window_size = min(7, len(amounts))
    recent_amounts = amounts[-window_size:]
    avg_amount = sum(recent_amounts) / len(recent_amounts)
    
    # Add slight growth trend if data shows it
    if len(amounts) >= 10:
        first_half = sum(amounts[:len(amounts)//2]) / (len(amounts)//2)
        second_half = sum(amounts[len(amounts)//2:]) / (len(amounts) - len(amounts)//2)
        growth_rate = (second_half - first_half) / first_half if first_half != 0 else 0
        growth_rate = min(max(growth_rate, -0.1), 0.1)  # Cap growth rate
    else:
        growth_rate = 0
    
    # Generate forecast
    forecast = []
    current_value = avg_amount
    
    for i in range(steps):
        current_value = current_value * (1 + growth_rate / 30)  # Daily growth
        forecast.append(round(current_value, 2))
    
    return forecast


def get_spending_insights(transactions, period_days=30):
    """
    Get spending insights for a period
    Returns a dictionary with insights
    """
    if not transactions:
        return {
            'total_spent': 0,
            'average_daily': 0,
            'top_categories': [],
            'trend': 'stable'
        }
    
    # Filter expenses
    expenses = [t for t in transactions if t.type == 'expense']
    
    if not expenses:
        return {
            'total_spent': 0,
            'average_daily': 0,
            'top_categories': [],
            'trend': 'stable'
        }
    
    # Calculate total spent
    total_spent = sum(t.amount_mad for t in expenses)
    
    # Calculate average daily spending
    average_daily = total_spent / period_days if period_days > 0 else 0
    
    # Get top categories
    category_totals = {}
    for t in expenses:
        category = t.category or 'Other'
        category_totals[category] = category_totals.get(category, 0) + t.amount_mad
    
    top_categories = sorted(
        [{'category': k, 'amount': round(v, 2)} for k, v in category_totals.items()],
        key=lambda x: x['amount'],
        reverse=True
    )[:5]
    
    # Determine trend
    if len(expenses) >= 10:
        mid_point = len(expenses) // 2
        first_half_avg = sum(t.amount_mad for t in expenses[:mid_point]) / mid_point
        second_half_avg = sum(t.amount_mad for t in expenses[mid_point:]) / (len(expenses) - mid_point)
        
        if second_half_avg > first_half_avg * 1.1:
            trend = 'increasing'
        elif second_half_avg < first_half_avg * 0.9:
            trend = 'decreasing'
        else:
            trend = 'stable'
    else:
        trend = 'stable'
    
    return {
        'total_spent': round(total_spent, 2),
        'average_daily': round(average_daily, 2),
        'top_categories': top_categories,
        'trend': trend
    }