import io
import time

from PIL import Image
from seedsigner.hardware.pivideostream import PiVideoStream
from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.models.singleton import Singleton



class Camera(Singleton):
    _video_stream = None
    _picamera = None
    _camera_rotation = None

    @classmethod
    def get_instance(cls):
        # This is the only way to access the one and only Controller
        if cls._instance is None:
            cls._instance = cls.__new__(cls)
        cls._instance._camera_rotation = int(Settings.get_instance().get_value(SettingsConstants.SETTING__CAMERA_ROTATION))
        return cls._instance


    def start_video_stream_mode(self, resolution=(512, 384), framerate=12, format="bgr"):
        from seedsigner.hardware.pivideostream import PiVideoStream
        if self._video_stream is not None:
            self.stop_video_stream_mode()
            # Pi Zero MMAL layer closes asynchronously; without this pause the
            # next PiCamera() call conflicts with ongoing teardown and produces
            # no frames, causing the scan loop to spin at 100% CPU indefinitely.
            time.sleep(1.0)

        self._video_stream = PiVideoStream(resolution=resolution,framerate=framerate, format=format)
        self._video_stream.start()

        # Wait up to 5 s for the first frame. On Pi Zero, the MMAL layer can
        # silently fail on a second PiCamera open — capture_continuous blocks
        # forever in the background thread, self.frame stays None, and the
        # ScanScreen loop spins with the button check unreachable. Detecting
        # this here lets us raise before ScanScreen takes over and hangs the UI.
        deadline = time.time() + 5.0
        while self._video_stream.read() is None and time.time() < deadline:
            time.sleep(0.05)

        if self._video_stream.read() is None:
            # Force-close the PiCamera to unblock the background thread.
            # We cannot call stop() here — it busy-waits on is_stopped, which
            # the stuck thread will never set. Closing the camera directly
            # causes picamera to interrupt capture_continuous in the thread.
            try:
                self._video_stream.camera.close()
            except Exception:
                pass
            self._video_stream = None
            raise RuntimeError(
                "Camera failed to start. Power the device off and back on to reset it."
            )


    def read_video_stream(self, as_image=False):
        if not self._video_stream:
            return None  # Camera stopped; callers check for None
        frame = self._video_stream.read()
        if not as_image:
            return frame
        else:
            if frame is not None:
                return Image.fromarray(frame.astype('uint8'), 'RGB').convert('RGBA').rotate(90 + self._camera_rotation)
        return None


    def stop_video_stream_mode(self):
        if self._video_stream is not None:
            vs = self._video_stream
            # Clear the instance reference first so LivePreviewThread's
            # _video_stream is None check fires and it stops rendering.
            self._video_stream = None

            # Signal the background camera thread to stop.
            vs.should_stop = True

            # Wait up to 3 s for a clean shutdown — normal case: capture_continuous
            # yields one more frame, thread sees should_stop, closes camera, sets
            # is_stopped. Pathological case on Pi Zero: MMAL stalls between frames
            # and the thread never gets to check should_stop, so is_stopped stays
            # False forever. Without this timeout the UI thread busy-waits forever,
            # buttons go dead, last camera frame frozen on screen.
            deadline = time.time() + 3.0
            while not vs.is_stopped and time.time() < deadline:
                time.sleep(0.05)

            if not vs.is_stopped:
                # MMAL stalled — force-close the PiCamera to interrupt
                # capture_continuous in the stuck thread so it can exit.
                try:
                    vs.camera.close()
                except Exception:
                    pass

            # Give MMAL time to fully release hardware before the next open.
            time.sleep(1.0)


    def start_single_frame_mode(self, resolution=(720, 480)):
        from picamera import PiCamera
        if self._video_stream is not None:
            self.stop_video_stream_mode()
        if self._picamera is not None:
            self._picamera.close()

        self._picamera = PiCamera(resolution=resolution, framerate=24)
        self._picamera.start_preview()


    def capture_frame(self):
        if self._picamera is None:
            raise Exception("Must call start_single_frame_mode first.")

        # Set auto-exposure values
        self._picamera.shutter_speed = self._picamera.exposure_speed
        self._picamera.exposure_mode = 'off'
        g = self._picamera.awb_gains
        self._picamera.awb_mode = 'off'
        self._picamera.awb_gains = g

        stream = io.BytesIO()
        self._picamera.capture(stream, format='jpeg')

        # "Rewind" the stream to the beginning so we can read its content
        stream.seek(0)
        return Image.open(stream).rotate(90 + self._camera_rotation)


    def stop_single_frame_mode(self):
        if self._picamera is not None:
            self._picamera.close()
            self._picamera = None

