import { useState, useRef, useEffect, type MouseEvent } from 'react';

export const useModal = () => {
    const [position, setPosition] = useState({ x: 0, y: 0 });
    const [isDragging, setIsDragging] = useState(false);
    const [offset, setOffset] = useState({ x: 0, y: 0 });
    const modalRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (modalRef.current) {
            const { innerWidth } = window;
            const { offsetWidth } = modalRef.current;

            const centerX = (innerWidth - offsetWidth) / 2;
            const topY = 100; // Position 100px from the top

            setPosition({ x: centerX, y: topY });
        }
    }, []);

    const onMouseDown = (e: MouseEvent<HTMLDivElement>) => {
        if (modalRef.current) {
            setIsDragging(true);
            setOffset({
                x: e.clientX - modalRef.current.getBoundingClientRect().left,
                y: e.clientY - modalRef.current.getBoundingClientRect().top,
            });
        }
    };

    const onMouseMove = (e: MouseEvent<HTMLDivElement>) => {
        if (isDragging && modalRef.current) {
            e.preventDefault();
            setPosition({
                x: e.clientX - offset.x,
                y: e.clientY - offset.y,
            });
        }
    };

    const onMouseUp = () => {
        setIsDragging(false);
    };

    useEffect(() => {
        const handleMouseUp = () => setIsDragging(false);
        window.addEventListener('mouseup', handleMouseUp);
        return () => {
            window.removeEventListener('mouseup', handleMouseUp);
        };
    }, []);

    return {
        position,
        modalRef,
        onMouseDown,
        onMouseMove,
        onMouseUp,
    };
};
