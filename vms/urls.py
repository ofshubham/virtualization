from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('on/', views.powerOn, name='powerOn'),
    path('off/', views.powerOff, name='powerOff'),
    path('check/',views.checkiftemplate,name='checkiftemplate'),
    path('clone/', views.clone, name='clone'),
    path('edit/', views.edit, name='edit'),
    path('destroy/', views.destroy, name='destroy'),
    path('stats/',views.stats,name='stats')

]
