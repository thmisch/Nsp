import threading

from kivy.app import App
from kivy.uix.button import Button

from kivy.utils import platform
import plyer

class TestApp(App):
    def build(self):
        s = platform + '|ay|'
        if platform == 'android':
            from android import loadingscreen
            loadingscreen.hide_loading_screen()
            from android.storage import app_storage_path
            s += app_storage_path()
        return Button(text=s)

if __name__ == '__main__':
    TestApp().run()
