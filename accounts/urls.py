from django.contrib import admin
from django.urls import path
from django.http import HttpResponse
from . import views

urlpatterns =[
    path('', views.dashboard, name='dashboard'),
    path('customers/<int:id>', views.customers, name='customers.show'),
    path('customer_profile/', views.customer_profile, name='customers.customer_profile'),
    path('customer_profile/setting', views.customer_profile_setting, name='customers.customer_profile_setting'),
    path('products/', views.products, name='products'),
    path('order/create/<int:customerId>', views.orderCreate, name='order.create'),
    path('order/update/<int:orderId>', views.orderUpdate, name='order.update'),
    path('order/delete/<int:orderId>', views.orderDelete, name='order.delete'),
    path('register/', views.register, name= 'register'),
    path('login/', views.userLogin, name= 'login'),
    path('logout/', views.userLogout, name= 'logout'),
    path('activate-email/', views.activate_email, name='activate-email'),
    path('verify-email/<str:pkb64>/<str:token>/',views.verify_email, name='verify-email'),

]
