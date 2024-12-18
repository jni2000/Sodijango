from django.db import models


# Create your models here.
class SoftwareSecurityScan(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    type = models.CharField(max_length=32, default="binary")
    name = models.TextField(default="")
    location = models.TextField(default="")
    level = models.CharField(max_length=32, default="default")
    note = models.TextField(default="None")
    status = models.CharField(max_length=32, editable=False, default="in-progress")
    ref_id = models.CharField(max_length=256, editable=False, default="1234-abcd")

    def __str__(self):
        return self.name
