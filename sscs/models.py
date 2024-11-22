from django.db import models

# Create your models here.
class SoftwareSecurityScan(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    type = models.CharField(max_length=32)
    name = models.TextField()
    location = models.TextField()
    note = models.TextField()

    def __str__(self):
        return self.name
