import ida_kernwin

from PyQt5.QtCore import QRect
from PyQt5.QtGui import QImage, QColor
from PyQt5.QtWidgets import QWidget

# ------------------------------------------------------------------------------
# IDA Util
# ------------------------------------------------------------------------------

# From Markus Gaasedelen
# https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse/util/ida.py


def get_ida_bg_color():
    """
    Get the background color of an IDA disassembly view. (IDA 7+)
    """
    names = ["Enums", "Structures"]
    names += ["Hex View-%u" % i for i in range(5)]
    names += ["IDA View-%c" % chr(ord('A') + i) for i in range(5)]

    # find a form (eg, IDA view) to analyze colors from
    for window_name in names:
        twidget = ida_kernwin.find_widget(window_name)
        if twidget:
            break
    else:
        raise RuntimeError("Failed to find donor view")

    # touch the target form so we know it is populated
    touch_window(twidget)

    # locate the Qt Widget for a form and take 1px image slice of it
    import sip
    widget = sip.wrapinstance(long(twidget), QWidget)
    pixmap = widget.grab(QRect(0, 10, widget.width(), 1))

    # convert the raw pixmap into an image (easier to interface with)
    image = QImage(pixmap.toImage())

    # return the predicted background color
    b, g, r, _ = QColor(predict_bg_color(image)).getRgb()
    return r << 16 | g << 8 | b


def touch_window(target):
    """
    Touch a window/widget/form to ensure it gets drawn by IDA.
    XXX/HACK:
      We need to ensure that widget we will analyze actually gets drawn
      so that there are colors for us to steal.
      To do this, we switch to it, and switch back. I tried a few different
      ways to trigger this from Qt, but could only trigger the full
      painting by going through the IDA routines.
    """

    # get the currently active widget/form title (the form itself seems
    # transient...)
    twidget = ida_kernwin.get_current_widget()
    title = ida_kernwin.get_widget_title(twidget)

    # touch the target window by switching to it
    ida_kernwin.activate_widget(target, True)

    # locate our previous selection
    previous_twidget = ida_kernwin.find_widget(title)

    # return us to our previous selection
    ida_kernwin.activate_widget(previous_twidget, True)


def predict_bg_color(image):
    """
    Predict the background color of an IDA View from a given image slice.
    We hypothesize that the 'background color' of a given image slice of an
    IDA form will be the color that appears in the longest 'streaks' or
    continuous sequences. This will probably be true 99% of the time.
    This function takes an image, and analyzes its first row of pixels. It
    will return the color that it believes to be the 'background color'
    based on its sequence length.
    """
    assert image.width() and image.height()

    # the details for the longest known color streak will be saved in these
    longest = 1
    speculative_bg = image.pixel(0, 0)

    # this will be the computed length of the current color streak
    sequence = 1

    # find the longest streak of color in a single pixel slice
    for x in xrange(1, image.width()):

        # the color of this pixel matches the last pixel, extend the streak
        # count
        if image.pixel(x, 0) == image.pixel(x-1, 0):
            sequence += 1

            #
            # this catches the case where the longest color streak is in
            # fact the last one. this ensures the streak color will get
            # saved.

            if x != image.width():
                continue

        # color change, determine if this was the longest continuous color
        # streak
        if sequence > longest:

            # save the last pixel as the longest seqeuence / most likely BG
            # color
            longest = sequence
            speculative_bg = image.pixel(x-1, 0)

            # reset the sequence counter
            sequence = 1

    # return the color we speculate to be the background color
    return speculative_bg
