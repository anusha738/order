from .models import User
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.urls import reverse_lazy
from django.template.loader import render_to_string
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponseRedirect
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from accounts.decorators import authenticated_user, admin_only, allowed_roles
from django.contrib.auth.models import Group
from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.forms import inlineformset_factory
from accounts.models import *
from accounts.forms import *
from .filters import *
from django.contrib.auth import authenticate,login,logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .forms import RegisterForm

# Create your views here.

@login_required(login_url='/login')
@allowed_roles(roles=['customer'])
def customer_profile(request):
    orders = request.user.customer.order_set.all()
    total = orders.count()
    delivered = orders.filter(status="delivered").count()
    pending = orders.filter(status="pending").count()
    return render(request, 'accounts/customer_profile.html', {
        'orders': orders,
        'total': total,
        'delivered': delivered,
        'pending': pending
    })

def customer_profile_setting(request):
    form = CustomerProfile(instance=request.user.customer)
    if request.method == "POST":
        form = CustomerProfile(request.POST, request.FILES, instance=request.user.customer)
        if form.is_valid():
            form.save()
            return redirect('/customer_profile')
    return render(request, 'accounts/profile_setting.html', {
        'form': form
    })

@login_required(login_url='/login')
@allowed_roles(roles=['admin'])
def customers(request, id):
    customer = Customer.objects.get(id = id)
    orders = customer.order_set.all()
    order_count = orders.count()
    filterObj = OrderFilter(request.GET, queryset=orders)
    orders = filterObj.qs
    return render(request, 'accounts/customers.html', {
        'customer' : customer,
        'orders' : orders,
        'order_count' : order_count,
        'filterObj' : filterObj
    })

@login_required(login_url='/login')
@allowed_roles(roles=['admin'])
def products(request):
    # return HttpResponse('contact pafe')
    products = Product.objects.all()
    return render(request, 'accounts/products.html', {
        'products' : products
    })

@login_required(login_url='/login') #if login, return dashbord. If not login , redirect to login page
@admin_only
def dashboard(request):
    # return HttpResponse('dashboard pafe')
    customers = Customer.objects.all()
    orders = Order.objects.all()
    total = orders.count()
    delivered = Order.objects.filter(status="delivered").count()
    pending = Order.objects.filter(status="pending").count()
    return render(request, 'accounts/dashboard.html', {
        'customers' : customers,
        'orders' : orders,
        'total' : total,
        'delivered' : delivered,
        'pending': pending
    })

@login_required(login_url='/login')
@allowed_roles(roles=['admin'])
def orderCreate(request, customerId):
    OrderFormSet = inlineformset_factory(Customer, Order, fields=('product', 'status'), extra=10)
    customer = Customer.objects.get(id = customerId)
    formset = OrderFormSet(instance=customer, queryset=Order.objects.none()) #need to add instance = customer to know whose formset is this 
    # form = OrderForm(initial= {'customer': customer})
    if request.method == "POST":

        formset = OrderFormSet(request.POST, instance=customer)
        if formset.is_valid():
            formset.save()
            return redirect('/')

    return render(request, 'accounts/order_form.html', {
        'formset' : formset
    })

@login_required(login_url='/login')
@allowed_roles(roles=['admin'])
def orderUpdate(request, orderId):
    order = Order.objects.get(id = orderId)
    form = OrderForm(instance=order)
    if request.method == "POST":
        form = OrderForm(request.POST, instance=order) #should add instance you want to update
        if form.is_valid():
            form.save()
            return redirect('/')

    return render(request, 'accounts/order_form.html', {
        'form' : form
    })

@login_required(login_url='/login')
@allowed_roles(roles=['admin'])
def orderDelete(request, orderId):
    order = Order.objects.get(id=orderId)
    if request.method == "POST":
        order.delete()
        return redirect('/')
    return render(request, 'accounts/order_delete.html', {
        'order': order
    })





@authenticated_user
def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # Set the user's active status to False
            user.save()
            # Generate verification token
            token = default_token_generator.make_token(user)
            # Create and send verification email
            verification_link = request.build_absolute_uri(reverse_lazy(
                'verify-email', args=[urlsafe_base64_encode(force_bytes(user.pk)), token]))
            subject = 'Activate your account'
            message = render_to_string('accounts/email_verification.txt', {
                'verification_link': verification_link,
            })
            send_mail(subject, message, 'noreply@example.com',[user.email], fail_silently=False)
            # Redirect the user to the activate email view
            return redirect('activate-email')
    else:
        form = RegisterForm()
    return render(request, 'accounts/register.html', {'form': form})
def activate_email(request):
    return render(request, 'accounts/activate_email.html')
def verify_email(request, pkb64, token):
    try:
        pk = force_text(urlsafe_base64_decode(pkb64))
        user = User.objects.get(pk=pk)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, 'accounts/verify_email_success.html')
    else:
        return render(request, 'accounts/verify_email_fail.html')

'''login function'''
@authenticated_user
def userLogin(request):
    if request.method == "POST":
        username = request.POST['username'] #[username] ka login.html mhr label htl ka username so tae name
        password = request.POST['password']

        user = authenticate(request, username = username, password = password) #authenticate() ka db htl mhr htae htr tae data twy shi lr sit, shi yin user yaw obj ko pay ml ,ma shi yin none pay ml
        if user is not None:
            login(request, user)
            return redirect('/')
        else:
            messages.error(request, 'username and password is incorrect')
            return redirect('/login')
    return render(request, 'accounts/login.html')

'''logout function'''
@login_required(login_url='/login')
def userLogout(request):
    logout(request)
    return redirect('/login')